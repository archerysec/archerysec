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

import defusedxml.ElementTree as ET
from django.core.files.uploadedfile import UploadedFile
from django.shortcuts import HttpResponseRedirect, render, reverse
from lxml import etree
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import (AllowAny, BasePermission,
                                        IsAuthenticated)
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archeryapi.models import OrgAPIKey
from archeryapi.serializers import OrgAPIKeySerializer
from compliance.models import DockleScanDb, InspecScanDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from projects.models import MonthDb, ProjectDb
from projects.serializers import (ProjectCreateSerializers,
                                  ProjectDataSerializers)
from scanners.scanner_parser.compliance_parser import (dockle_json_parser,
                                                       inspec_json_parser)
from scanners.scanner_parser.network_scanner import (Nessus_Parser,
                                                     OpenVas_Parser)
from scanners.scanner_parser.staticscanner_parser import (
    brakeman_json_report_parser, checkmarx_xml_report_parser,
    clair_json_report_parser, dependencycheck_report_parser,
    gitlab_container_json_report_parser,
    gitlab_sast_json_report_parser, gitlab_sca_json_report_parser,
    nodejsscan_report_json, npm_audit_report_json, semgrep_json_report_parser,
    tfsec_report_parser, trivy_json_report_parser,
    twistlock_json_report_parser, whitesource_json_report_parser)
from scanners.scanner_parser.staticscanner_parser.findbugs_report_parser import FindsecbugsParser
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import \
    bandit_report_json
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from scanners.scanner_parser.web_scanner import (acunetix_xml_parser,
                                                 arachni_xml_parser,
                                                 burp_xml_parser,
                                                 netsparker_xml_parser,
                                                 webinspect_xml_parser,
                                                 zap_xml_parser)
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from tools.models import NiktoResultDb
from user_management import permissions
from user_management.models import Organization, UserProfile
from webscanners.models import WebScanResultsDb, WebScansDb
from cicd.models import CicdDb
from cicd.serializers import GetPoliciesSerializers


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

    def web_result_data(self, scan_id, project_uu_id, scanner):
        all_web_data = WebScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_web_data)
        total_high = len(all_web_data.filter(severity="High"))
        total_medium = len(all_web_data.filter(severity="Medium"))
        total_low = len(all_web_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": project_uu_id,
                "scan_id": scan_id,
                "scanner": scanner,
                "result": {
                    "total_vul": total_vul,
                    "total_high": total_high,
                    "total_medium": total_medium,
                    "total_low": total_low,
                },
            }
        )

    def sast_result_data(self, scan_id, project_uu_id, scanner):
        all_sast_data = StaticScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_sast_data)
        total_high = len(all_sast_data.filter(severity="High"))
        total_medium = len(all_sast_data.filter(severity="Medium"))
        total_low = len(all_sast_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": project_uu_id,
                "scan_id": scan_id,
                "scanner": scanner,
                "result": {
                    "total_vul": total_vul,
                    "total_high": total_high,
                    "total_medium": total_medium,
                    "total_low": total_low,
                },
            }
        )

    def network_result_data(self, scan_id, project_uu_id, scanner):
        all_net_data = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_net_data)
        total_high = len(all_net_data.filter(severity="High"))
        total_medium = len(all_net_data.filter(severity="Medium"))
        total_low = len(all_net_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": project_uu_id,
                "scan_id": scan_id,
                "scanner": scanner,
                "result": {
                    "total_vul": total_vul,
                    "total_high": total_high,
                    "total_medium": total_medium,
                    "total_low": total_low,
                },
            }
        )

    def post(self, request, format=None):
        date_time = datetime.datetime.now()
        project_uu_id = request.data.get("project_id")
        project_id = (
            ProjectDb.objects.filter(uu_id=project_uu_id).values("id").get()["id"]
        )
        print(project_id)
        scanner = request.data.get("scanner")
        if isinstance(request.data.get("filename"), UploadedFile):
            file = request.data.get("filename").read().decode("utf-8")
        else:
            file = request.data.get("filename")

        scan_url = request.data.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Zap",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)

            zap_xml_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml_en,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "burp_scan":

            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Burp",
            )
            scan_dump.save()
            # Burp scan XML parser
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)

            burp_xml_parser.burp_scan_data(
                root_xml_en,
                project_id,
                scan_id,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "arachni":

            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Arachni",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            arachni_xml_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml,
                target_url=scan_url,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "acunetix":

            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Acunetix",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)
            acunetix_xml_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml_en,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "netsparker":

            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Netsparker",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            netsparker_xml_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "webinspect":

            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Webinspect",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            webinspect_xml_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml,
            )
            return self.web_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "banditscan":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Bandit",
                date_time=date_time,
            )
            scan_dump.save()
            data = json.loads(file)
            bandit_report_json(
                data=data,
                project_id=project_id,
                scan_id=scan_id,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "dependencycheck":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Dependencycheck",
            )
            scan_dump.save()
            xml_dat = bytes(bytearray(file, encoding="utf-8"))
            data = etree.XML(xml_dat)
            dependencycheck_report_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "findbugs":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Findbugs",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            findbugs_report_parser = FindsecbugsParser(project_id=project_id,
                                                       scan_id=scan_id,
                                                       root=root_xml)
            findbugs_report_parser.xml_parser()
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "checkmarx":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Checkmarx",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            checkmarx_xml_report_parser.checkmarx_report_xml(
                data=root_xml,
                project_id=project_id,
                scan_id=scan_id,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "clair":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Clair",
            )
            scan_dump.save()
            data = json.loads(file)
            clair_json_report_parser.clair_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "trivy":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Trivy",
            )
            scan_dump.save()
            data = json.loads(file)
            trivy_json_report_parser.trivy_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "gitlabsca":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Gitlabsca",
            )
            scan_dump.save()
            data = json.loads(file)
            gitlab_sca_json_report_parser.gitlabsca_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "gitlabsast":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Gitlabsast",
            )
            scan_dump.save()
            data = json.loads(file)
            gitlab_sast_json_report_parser.gitlabsast_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "gitlabcontainerscan":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Gitlabcontainerscan",
            )
            scan_dump.save()
            data = json.loads(file)
            gitlab_container_json_report_parser.gitlabcontainerscan_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "npmaudit":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Npmaudit",
            )
            scan_dump.save()
            data = json.loads(file)
            npm_audit_report_json.npmaudit_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "nodejsscan":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Nodejsscan",
            )
            scan_dump.save()
            data = json.loads(file)
            nodejsscan_report_json.nodejsscan_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "semgrepscan":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Semgrepscan",
            )
            scan_dump.save()
            data = json.loads(file)
            semgrep_json_report_parser.semgrep_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "tfsec":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Tfsec",
            )
            scan_dump.save()
            data = json.loads(file)
            tfsec_report_parser.tfsec_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "whitesource":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Whitesource",
            )
            scan_dump.save()
            data = json.loads(file)
            whitesource_json_report_parser.whitesource_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "inspec":

            scan_dump = InspecScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
            )
            scan_dump.save()
            data = json.loads(file)
            inspec_json_parser.inspec_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_uu_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "dockle":

            scan_dump = DockleScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
            )
            scan_dump.save()
            data = json.loads(file)
            dockle_json_parser.dockle_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_uu_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "nessus":
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)
            Nessus_Parser.updated_nessus_parser(
                root=root_xml_en,
                scan_id=scan_id,
                project_id=project_id,
            )
            return self.network_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "openvas":

            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)
            hosts = OpenVas_Parser.get_hosts(root_xml_en)
            for host in hosts:
                scan_dump = NetworkScanDb(
                    ip=host,
                    scan_id=scan_id,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Openvas",
                )
                scan_dump.save()
            OpenVas_Parser.updated_xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml_en,
            )
            return self.network_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "nikto":

            scan_dump = NiktoResultDb(
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
            )
            scan_dump.save()

            nikto_html_parser(
                file,
                project_id,
                scan_id,
            )
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_uu_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "twistlock":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Twistlock",
            )
            scan_dump.save()
            data = json.loads(file)
            twistlock_json_report_parser.twistlock_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        elif scanner == "brakeman":

            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Brakeman",
            )
            scan_dump.save()
            data = json.loads(file)
            brakeman_json_report_parser.brakeman_report_json(
                project_id=project_id,
                scan_id=scan_id,
                data=data,
            )
            return self.sast_result_data(scan_id, project_uu_id, scanner)

        else:
            return Response({"message": "Scanner Not Found"})


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
            {"all_active_keys": all_active_keys, "serialized_data": serialized_data},
        )

    def post(self, request):
        user = request.user

        api_key = self.generate_api_key(user)
        name = request.POST.get("name")

        new_api_key = OrgAPIKey.objects.create(
            api_key=api_key, created_by=user, name=name
        )

        content = {"APIKey": api_key, "id": new_api_key.uu_id}
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
        if uu_id == None:
            get_cicd_policies = CicdDb.objects.all()
            serialized_data = GetPoliciesSerializers(get_cicd_policies, many=True)
        else:
            try:
                get_cicd_policies = CicdDb.objects.get(cicd_id=uu_id)
                serialized_data = GetPoliciesSerializers(get_cicd_policies, many=False)
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
