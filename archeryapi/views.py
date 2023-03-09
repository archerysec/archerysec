# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import datetime
import json
import secrets
import uuid
import csv
import io
import os

import defusedxml.ElementTree as ET
from django.core.files.uploadedfile import UploadedFile
from django.shortcuts import HttpResponseRedirect, render, reverse
from django.db.models import TextField, F, Value
from django.db.models.functions import Cast, Concat
from django.db import transaction
from lxml import etree
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import (AllowAny, BasePermission,
                                        IsAuthenticated)
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archeryapi.models import OrgAPIKey
from archeryapi.serializers import OrgAPIKeySerializer, GenericScanResultsDbSerializer
from compliance.models import DockleScanDb, InspecScanDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from projects.models import MonthDb, ProjectDb
from projects.serializers import (ProjectCreateSerializers,
                                  ProjectDataSerializers)

from scanners.scanner_parser.network_scanner import OpenVas_Parser

from staticscanners.models import StaticScanResultsDb, StaticScansDb
from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from tools.models import NiktoResultDb
from user_management import permissions
from user_management.models import Organization, UserProfile
from webscanners.models import WebScanResultsDb, WebScansDb
from cicd.models import CicdDb
from cicd.serializers import GetPoliciesSerializers
from django.utils.html import escape
from scanners.scanner_parser import scanner_parser

from jiraticketing.models import jirasetting
from django.core import signing
from jira import JIRA


class CreateProject(APIView):
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def post(self, request):
        """
        Current user's identity endpoint.
        """
        _project_name = None
        _project_id = None

        serializer = ProjectDataSerializers(data=request.data)
        if serializer.is_valid():
            project_name = request.data.get(
                "project_name",
            )

            project_disc = request.data.get(
                "project_disc",
            )

            all_project = ProjectDb.objects.filter(project_name=project_name)

            for project in all_project:
                _project_name = project.project_name
                _project_id = project.uu_id

            if _project_name == project_name:
                return Response(
                    {"message": "Project already existed", "project_id": _project_id}
                )

            else:
                project = ProjectDb(
                    project_name=project_name,
                    project_disc=project_disc,
                    # created_by=request.user,
                    total_vuln=0,
                    total_high=0,
                    total_medium=0,
                    total_low=0,
                    total_open=0,
                    total_false=0,
                    total_close=0,
                    total_net=0,
                    total_web=0,
                    total_static=0,
                    high_net=0,
                    high_web=0,
                    high_static=0,
                    medium_net=0,
                    medium_web=0,
                    medium_static=0,
                    low_net=0,
                    low_web=0,
                    low_static=0,
                )
                project.save()

                all_month_data_display = MonthDb.objects.filter()

                if len(all_month_data_display) == 0:
                    save_months_data = MonthDb(
                        project_id=project.id,
                        month=datetime.datetime.now().month,
                        high=0,
                        medium=0,
                        low=0,
                    )
                    save_months_data.save()

                if not project_name:
                    return Response({"error": "No name passed"})
                return Response(
                    {"message": "Project Created", "project_id": project.uu_id}
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UploadScanResult(APIView):
    parser_classes = (MultiPartParser,)
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def check_file_ext(self, file):
        split_tup = os.path.splitext(file)
        file_extension = split_tup[1]
        return file_extension

    def web_result_data(self, scan_id, project_uu_id, scanner):
        all_web_data = WebScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_web_data)
        total_critical = len(all_web_data.filter(severity="Critical"))
        total_high = len(all_web_data.filter(severity="High"))
        total_medium = len(all_web_data.filter(severity="Medium"))
        total_low = len(all_web_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def sast_result_data(self, scan_id, project_uu_id, scanner):
        all_sast_data = StaticScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_sast_data.filter(
            severity__in=['Critical', 'High', 'Medium', 'Low']))
        total_critical = len(all_sast_data.filter(severity="Critical"))
        total_high = len(all_sast_data.filter(severity="High"))
        total_medium = len(all_sast_data.filter(severity="Medium"))
        total_low = len(all_sast_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def cloud_result_data(self, scan_id, project_uu_id, scanner):
        all_cloud_data = CloudScansResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_cloud_data)
        total_critical = len(all_cloud_data.filter(severity="Critical"))
        total_high = len(all_cloud_data.filter(severity="High"))
        total_medium = len(all_cloud_data.filter(severity="Medium"))
        total_low = len(all_cloud_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                    "total_critical": escape(total_critical)
                },
            }
        )

    def network_result_data(self, scan_id, project_uu_id, scanner):
        all_net_data = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_net_data)
        total_critical = len(all_net_data.filter(severity="Critical"))
        total_high = len(all_net_data.filter(severity="High"))
        total_medium = len(all_net_data.filter(severity="Medium"))
        total_low = len(all_net_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def post(self, request, format=None):
        date_time = datetime.datetime.now()
        project_uu_id = request.data.get("project_id")
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id).values("id").get()["id"]
        )
        scanner = request.data.get("scanner")
        if isinstance(request.data.get("filename"), UploadedFile):
            file = request.data.get("filename").read().decode("utf-8")
        else:
            file = request.data.get("filename")

        scan_url = request.data.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"

        parser_dict = scanner_parser.parser_function_dict.get(scanner, "Not implemented")
        if parser_dict == "Not implemented":
            return Response(
                {
                    "error": "Scanner is not implemented",
                }, status=status.HTTP_400_BAD_REQUEST
            )
        filetype = parser_dict.get("type", "Unknown")
        if filetype == "Unknown":
            return Response(
                {
                    "error": "Unknown file type",
                }, status=status.HTTP_400_BAD_REQUEST
            )

        # Put the data in memory
        if filetype == "XML" or filetype == "Nessus":
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            data = ET.fromstring(en_root_xml)
        elif filetype == "LXML":
            xml_dat = bytes(bytearray(file, encoding="utf-8"))
            data = etree.XML(xml_dat)
        elif filetype == "JSON":
            data = json.loads(file)
        elif filetype == "CSV":
            reader = csv.DictReader(io.StringIO(file))
            data = [line for line in reader]
        # Custom data loader
        elif filetype == "JS":
            file_data = file.replace('scoutsuite_results =', '').lstrip()
            json_payload = ''.join(file_data)
            data = json.loads(json_payload)
        # Unsupported file type case
        else:
            return Response(
                {
                    "error": "Unsupported file type",
                }, status=status.HTTP_400_BAD_REQUEST
            )

        db_type = parser_dict.get("dbtype", "Unsupported")
        if db_type == "Unsupported":
            return Response(
                {
                    "error": "Unsupported DB type",
                }, status=status.HTTP_400_BAD_REQUEST
            )
        need_to_store = True
        custom_return = False
        # Store to database - regular types
        if "dbname" in parser_dict:
            db_name = parser_dict.get("dbname", "Unknown")
            if db_type == "WebScans":
                return_func = self.web_result_data
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner=db_name,
                )
            elif db_type == "StaticScans":
                return_func = self.sast_result_data
                scan_dump = StaticScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner=db_name,
                )
            elif db_type == "NetworkScan":
                return_func = self.network_result_data
                # OpenVAS special case
                if scanner == "openvas":
                    need_to_store = False
                    hosts = OpenVas_Parser.get_hosts(root_xml)
                    for host in hosts:
                        scan_dump = NetworkScanDb(
                            ip=host,
                            scan_id=scan_id,
                            project_id=project_id,
                            scan_status=scan_status,
                            scanner=db_name,
                        )
                        scan_dump.save()
                # Regular network scan case
                else:
                    host = parser_dict["getHostFunction"](data)
                    scan_dump = NetworkScanDb(
                        ip=host,
                        scan_id=scan_id,
                        project_id=project_id,
                        scan_status=scan_status,
                        scanner=db_name,
                    )
            elif db_type == "CloudScans":
                return_func = self.cloud_result_data
                scan_dump = CloudScansDb(
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    rescan="No",
                    scanner=db_name,
                )
        # Store to database - custom types
        elif db_type == "NiktoResult":
            custom_return = True
            scan_dump = NiktoResultDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
            )
        elif db_type == "InspecScan":
            custom_return = True
            scan_dump = InspecScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
            )
        elif db_type == "DockleScan":
            custom_return = True
            scan_dump = DockleScanDb(
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
            )
        elif db_type == "Nessus":
            return_func = self.network_result_data
            need_to_store = False
            # Nessus does not store before the parser
        # Store the dump (except for no need to store cases)
        if need_to_store is True:
            scan_dump.save()

        # Call the parser
        parser_func = parser_dict["parserFunction"]
        parser_func(data, project_id, scan_id)

        # Success !
        if custom_return is True:
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": escape(project_uu_id),
                    "scan_id": escape(scan_id),
                    "scanner": escape(scanner),
                }
            )
        else:
            return return_func(scan_id, project_id, scanner)


class APIKey(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "access-key/access-key-list.html"
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        all_active_keys = OrgAPIKey.objects.filter(is_active=True)

        serialized_data = OrgAPIKeySerializer(all_active_keys, many=True)
        return render(
            request,
            "access-key/access-key-list.html",
            {"all_active_keys": all_active_keys,
                "serialized_data": serialized_data},
        )

    def post(self, request):
        user = request.user

        api_key = self.generate_api_key(user)
        name = request.POST.get("name")

        # new_api_key =
        OrgAPIKey.objects.create(
            api_key=api_key, created_by=user, name=name
        )

        # content = {"APIKey": api_key, "id": new_api_key.uu_id}
        return HttpResponseRedirect("/api/access-key/")

    def generate_api_key(self, user: UserProfile) -> str:
        """
        return string api key
        """
        api_key = secrets.token_urlsafe(48)

        return api_key


class DisableAPIKey(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def put(self, request, api_key_uuid):
        user = request.user
        current_org = user.organization

        key_object = OrgAPIKey.objects.filter(
            org_subscription=current_org, is_active=True, uu_id=api_key_uuid
        ).update(is_active=False)

        if key_object > 0:
            content = {"message": "API Key Deactivate"}
            http_status = status.HTTP_200_OK
        else:
            content = {"message": "API Key Not Found"}
            http_status = status.HTTP_404_NOT_FOUND

        return Response(content, http_status)


class GetCicdPolicies(APIView):
    parser_classes = (MultiPartParser,)
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def get(self, request, uu_id=None):
        if uu_id is None:
            get_cicd_policies = CicdDb.objects.all()
            serialized_data = GetPoliciesSerializers(
                get_cicd_policies, many=True)
        else:
            try:
                get_cicd_policies = CicdDb.objects.get(cicd_id=uu_id)
                serialized_data = GetPoliciesSerializers(
                    get_cicd_policies, many=False)
            except CicdDb.DoesNotExist:
                return Response(
                    {"message": "CI/CD Id Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)


class DeleteAPIKey(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def post(self, request):
        uu_id = request.POST.get("uu_id")

        scan_item = str(uu_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            uu_id = value_split.__getitem__(i)

            item = OrgAPIKey.objects.filter(uu_id=uu_id)
            item.delete()
        return HttpResponseRedirect("/api/access-key/")


class ApiTest(APIView):
    permission_classes = ()

    def get(self, request):
        return Response(
            {"message": "ArcherySec API working."}
        )


class ListAllScanResults(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):

        # Retrieve the filter parameters
        # scan_filter = request.GET.get("scan_filter", None)

        # Get scan list
        all_cloud_data = CloudScansResultsDb.objects.annotate(
            target=Concat('cloudAccountId', Value(' '), 'cloudType', output_field=TextField())
        ).values(
            'scan_id',
            'project_id',
            'date_time',
            'vuln_id',
            'false_positive',
            'severity_color',
            'dup_hash',
            'vuln_duplicate',
            'false_positive_hash',
            'vuln_status',
            'jira_ticket',
            'title',
            'severity',
            'description',
            'solution',
            'scanner',
            'target'
        )

        all_network_data = NetworkScanResultsDb.objects.annotate(
            target=Concat(Cast('ip', output_field=TextField()), Value(':'), 'port', output_field=TextField())
        ).values(
            'scan_id',
            'project_id',
            'date_time',
            'vuln_id',
            'false_positive',
            'severity_color',
            'dup_hash',
            'vuln_duplicate',
            'false_positive_hash',
            'vuln_status',
            'jira_ticket',
            'title',
            'severity',
            'description',
            'solution',
            'scanner',
            'target'
        )

        all_sast_data = StaticScanResultsDb.objects.annotate(
            target=Concat('filePath', Value("/"), 'fileName', output_field=TextField())
        ).values(
            'scan_id',
            'project_id',
            'date_time',
            'vuln_id',
            'false_positive',
            'severity_color',
            'dup_hash',
            'vuln_duplicate',
            'false_positive_hash',
            'vuln_status',
            'jira_ticket',
            'title',
            'severity',
            'description',
            'solution',
            'scanner',
            'target'
        )

        all_web_data = WebScanResultsDb.objects.annotate(
            target=F('url')
        ).values(
            'scan_id',
            'project_id',
            'date_time',
            'vuln_id',
            'false_positive',
            'severity_color',
            'dup_hash',
            'vuln_duplicate',
            'false_positive_hash',
            'vuln_status',
            'jira_ticket',
            'title',
            'severity',
            'description',
            'solution',
            'scanner',
            'target'
        )

        # Filter resulting queries
        # for tables in [all_cloud_data, all_web_data, all_network_data, all_sast_data]:
        #     if scan_filter is not None:
        #         if scan_filter == "nojira":
        #             tables = tables.filter(jira_ticket__isnull=True)

        # Tables of the world, unite !
        all_data = all_cloud_data.union(all_sast_data, all_network_data, all_web_data)

        serialized_data = GenericScanResultsDbSerializer(all_data, many=True)

        return Response(serialized_data.data, status=status.HTTP_200_OK)


class UpdateJiraTicket(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def post(self, request):

        # Retrieve the JSON object with the update
        if request.content_type == "application/json":
            parsed_input_data = request.data
        else:
            raw_input_data = request.POST.get("json_data", None)
            if raw_input_data is None:
                return Response({"error": "No data passed"}, status=status.HTTP_400_BAD_REQUEST)
            parsed_input_data = json.loads(raw_input_data)
        if len(parsed_input_data) == 0:
            return Response({"error": "Empty structure passed"}, status=status.HTTP_400_BAD_REQUEST)

        # Connect to Jira
        jira_setting = jirasetting.objects.filter()

        jira_server = ""
        jira_username = None
        jira_password = None
        jira_ser = ""

        for jira in jira_setting:
            jira_server = jira.jira_server
            jira_username = jira.jira_username
            jira_password = jira.jira_password

        if jira_username is not None:
            jira_username = signing.loads(jira_username)

        if jira_password is not None:
            jira_password = signing.loads(jira_password)

        options = {"server": jira_server}
        try:
            if jira_username is not None and jira_username != "" :
                jira_ser = JIRA(
                    options, basic_auth=(jira_username, jira_password), timeout=30
                )
            else :
                jira_ser = JIRA(options, token_auth=jira_password, timeout=30)
        except Exception:
            return Response({"error": "Cannot connect to JIRA"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Start the database transactional process
        try:
            with transaction.atomic():
                to_update = len(parsed_input_data)
                update_count = 0
                vulns_not_found = []

                # Update the entries
                for vuln_id, jira_tick in parsed_input_data.items():
                    linked_issue = None
                    if jira_tick is not None and jira_tick.strip() != "":
                        linked_issue = jira_ser.issue(jira_tick)

                    vuln_uuid = uuid.UUID(vuln_id)
                    found = False

                    matched_vuln = CloudScansResultsDb.objects.filter(vuln_id=vuln_uuid)
                    if len(matched_vuln) == 1:
                        matched_vuln.update(jira_ticket=linked_issue)
                        update_count += 1
                        found = True

                    if not found:
                        matched_vuln = WebScanResultsDb.objects.filter(vuln_id=vuln_uuid)
                        if len(matched_vuln) == 1:
                            matched_vuln.update(jira_ticket=linked_issue)
                            update_count += 1
                            found = True

                    if not found:
                        matched_vuln = NetworkScanResultsDb.objects.filter(vuln_id=vuln_uuid)
                        if len(matched_vuln) == 1:
                            matched_vuln.update(jira_ticket=linked_issue)
                            update_count += 1
                            found = True

                    if not found:
                        matched_vuln = StaticScanResultsDb.objects.filter(vuln_id=vuln_uuid)
                        if len(matched_vuln) == 1:
                            matched_vuln.update(jira_ticket=linked_issue)
                            update_count += 1
                            found = True

                    # This vuln has not been found, add it to the list
                    if not found:
                        vulns_not_found.append(vuln_id)

                if update_count != to_update:
                    raise Exception("Too many/few rows updated, rolling back...")

        except KeyError:
            return Response({"error": "KeyError: Something went wrong when updating"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception:
            return Response({"error": "General error"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Jira tickets have been updated"}, status=status.HTTP_200_OK)
