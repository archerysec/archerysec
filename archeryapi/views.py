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
import threading
from itertools import chain

import defusedxml.ElementTree as ET
from django.contrib.auth.models import User
from django.core.files.uploadedfile import UploadedFile
from lxml import etree
from rest_framework import generics, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from stronghold.decorators import public

from archeryapi.serializers import CreateUser
from compliance.models import DockleScanDb, InspecScanDb
from networkscanners import views
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from networkscanners.serializers import (NetworkScanDbSerializer,
                                         NetworkScanResultsDbSerializer)
from projects.models import MonthDb, ProjectDb
from projects.serializers import ProjectDataSerializers
from scanners.scanner_parser.compliance_parser import (dockle_json_parser,
                                                       inspec_json_parser)
from scanners.scanner_parser.network_scanner import (Nessus_Parser,
                                                     OpenVas_Parser)
from scanners.scanner_parser.staticscanner_parser import (
    brakeman_json_report_parser, checkmarx_xml_report_parser,
    clair_json_report_parser, dependencycheck_report_parser,
    findbugs_report_parser, gitlab_container_json_report_parser,
    gitlab_sast_json_report_parser, gitlab_sca_json_report_parser,
    nodejsscan_report_json, npm_audit_report_json, semgrep_json_report_parser,
    tfsec_report_parser, trivy_json_report_parser,
    twistlock_json_report_parser, whitesource_json_report_parser)
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import \
    bandit_report_json
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from scanners.scanner_parser.web_scanner import (acunetix_xml_parser,
                                                 arachni_xml_parser,
                                                 burp_xml_parser,
                                                 netsparker_xml_parser,
                                                 webinspect_xml_parser,
                                                 zap_xml_parser)
from scanners.scanner_plugin.web_scanner import burp_plugin
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from staticscanners.serializers import (StaticScanDbSerializer,
                                        StaticScanResultsDbSerializer)
from tools.models import NiktoResultDb
from webscanners.arachniscanner.views import launch_arachni_scan
from webscanners.models import WebScanResultsDb, WebScansDb
from webscanners.serializers import (UploadScanSerializer,
                                     WebScanResultsDbSerializer,
                                     WebScansDbSerializer,
                                     WebScanStatusSerializer,
                                     ZapScanStatusDataSerializers)
from webscanners.zapscanner.views import launch_zap_scan

import secrets
import uuid
from datetime import datetime
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from typing import Any, Dict, List

from user_management import permissions
from user_management.models import Organization, UserProfile
from archeryapi.models import OrgAPIKey
from archeryapi.serializers import OrgAPIKeySerializer


class WebScan(generics.ListCreateAPIView):
    queryset = WebScansDb.objects.all()
    serializer_class = WebScansDbSerializer

    def get(self, request, format=None, **kwargs):
        """
        GET List all scans and check status.
        """

        all_scans = WebScansDb.objects.filter()
        serialized_scans = WebScansDbSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
        Launch scans using this api
        """

        serializer = WebScansDbSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = uuid.uuid4()
            scanner = request.data.get("scanner")
            target_url = request.data.get(
                "scan_url",
            )
            project_id = request.data.get(
                "project_id",
            )
            rescanid = None
            rescan = "No"
            user = request.user
            if scanner == "zap_scan":
                # run_s = launch_zap_scan
                thread = threading.Thread(
                    target=launch_zap_scan,
                    args=(target_url, project_id, rescanid, rescan, scan_id, user),
                )
                thread.daemon = True
                thread.start()

            elif scanner == "burp_scan":
                user = request.user
                date_time = datetime.datetime.now()
                scan_dump = WebScansDb(
                    scan_id=scan_id,
                    project_id=project_id,
                    url=target_url,
                    date_time=date_time,
                    scanner="Burp",
                )
                scan_dump.save()
                try:
                    do_scan = burp_plugin.burp_scans(
                        project_id, target_url, scan_id, user
                    )
                    thread = threading.Thread(
                        target=do_scan.scan_launch,
                    )
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    print(e)
            elif scanner == "arachni":
                thread = threading.Thread(
                    target=launch_arachni_scan,
                    args=(target_url, project_id, rescanid, rescan, scan_id, user),
                )
                thread.daemon = True
                thread.start()

            if not target_url:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Launched", "scanid": scan_id})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetworkScan(generics.ListCreateAPIView):
    """
    Network Scan API call to perform scan.
    """

    # queryset = openvas_scan_db.objects.all()
    serializer_class = NetworkScanDbSerializer

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = NetworkScanDb.objects.filter()
        serialized_scans = NetworkScanDbSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
        Current user's identity endpoint.

        """
        user = request.user
        serializer = NetworkScanDbSerializer(data=request.data)
        if serializer.is_valid():
            target_ip = request.data.get(
                "scan_ip",
            )
            project_id = request.data.get(
                "project_id",
            )
            profile = None
            # views.openvas_scanner(target_ip, project_id, profile)
            thread = threading.Thread(
                target=views.openvas_scanner,
                args=(target_ip, project_id, profile, user),
            )
            thread.daemon = True
            thread.start()
            # time.sleep(5)
            if not target_ip:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Started"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Project(generics.CreateAPIView):
    queryset = ProjectDb.objects.all()
    serializer_class = ProjectDataSerializers

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = ProjectDb.objects.filter()
        serialized_scans = ProjectDataSerializers(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
        Current user's identity endpoint.

        """
        _project_name = None
        _project_id = None

        serializer = ProjectDataSerializers(data=request.data)
        if serializer.is_valid():
            project_id = uuid.uuid4()
            project_name = request.data.get(
                "project_name",
            )
            project_start = request.data.get(
                "project_start",
            )
            project_end = request.data.get(
                "project_end",
            )
            project_owner = request.data.get(
                "project_owner",
            )
            project_disc = request.data.get(
                "project_disc",
            )

            date_time = datetime.datetime.now()

            all_project = ProjectDb.objects.filter(project_name=project_name)

            for project in all_project:
                _project_name = project.project_name
                _project_id = project.project_id

            if _project_name == project_name:
                return Response(
                    {"message": "Project already existed", "project_id": _project_id}
                )

            else:
                save_project = ProjectDb(
                    project_name=project_name,
                    project_id=project_id,
                    project_start=project_start,
                    project_end=project_end,
                    project_owner=project_owner,
                    project_disc=project_disc,
                    date_time=date_time,
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
                save_project.save()

                save_months_data = MonthDb(
                    project_id=project_id,
                    month=datetime.datetime.now().month,
                    high=0,
                    medium=0,
                    low=0,
                )
                save_months_data.save()

                if not project_name:
                    return Response({"error": "No name passed"})
                return Response(
                    {"message": "Project Created", "project_id": project_id}
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WebScanResult(generics.ListCreateAPIView):
    queryset = WebScanResultsDb.objects.all()
    serializer_class = WebScanResultsDbSerializer

    def post(self, request, format=None, **kwargs):
        """
        Post request to get all vulnerability Data.
        """
        serializer = WebScanResultsDbSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get(
                "scan_id",
            )
            zap_scan = WebScanResultsDb.objects.filter(scan_id=scan_id, scanner="zap")
            burp_scan = WebScanResultsDb.objects.filter(scan_id=scan_id, scanner="Burp")
            all_scans = chain(zap_scan, burp_scan)
            serialized_scans = WebScanResultsDbSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


class ZapScanStatus(generics.ListCreateAPIView):
    serializer_class = WebScanStatusSerializer

    def post(self, request, format=None, **kwargs):
        """
        Post request to get all vulnerability Data.
        """
        username = request.user.username

        serializer = WebScanStatusSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get(
                "scan_scanid",
            )
            zap_scan = WebScansDb.objects.filter(scan_id=scan_id)
            all_scans = chain(zap_scan)
            serialized_scans = WebScanStatusSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


class UpdateZapStatus(generics.CreateAPIView):
    queryset = WebScansDb.objects.all()

    def post(self, request, format=None, **kwargs):
        username = request.user.username
        serializer = ZapScanStatusDataSerializers(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get("scan_id")
            scan_status = request.data.get("scan_status")
            WebScansDb.objects.filter(scan_id=scan_id).update(scan_status=scan_status)
            return Response(
                {"message": "ZAP Scanner status updated %s", "Scan Status": scan_status}
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UploadScanResult(APIView):
    parser_classes = (MultiPartParser,)

    def post(self, request, format=None):
        project_id = request.data.get("project_id")
        scanner = request.data.get("scanner")
        if isinstance(request.data.get("filename"), UploadedFile):
            file = request.data.get("filename").read().decode("utf-8")
        else:
            file = request.data.get("filename")

        scan_url = request.data.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        # add your scanner here
        if scanner == "zap_scan":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "ZAP Scan Data Uploaded",
                    "scanner": scanner,
                    "project_id": project_id,
                    "scan_id": scan_id,
                }
            )
        elif scanner == "burp_scan":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Burp Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "arachni":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "acunetix":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "netsparker":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )
        elif scanner == "webinspect":
            date_time = datetime.datetime.now()
            scan_dump = WebScansDb(
                scan_url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "banditscan":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Banditscan",
            )
            scan_dump.save()
            data = json.loads(file)
            bandit_report_json(
                data=data,
                project_id=project_id,
                scan_id=scan_id,
            )
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "dependencycheck":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )
        elif scanner == "findbugs":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                scanner="Findbugs",
            )
            scan_dump.save()
            root_xml = ET.fromstring(file)
            findbugs_report_parser.xml_parser(
                project_id=project_id,
                scan_id=scan_id,
                root=root_xml,
            )
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "checkmarx":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )
        elif scanner == "clair":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "trivy":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "gitlabsca":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "gitlabsast":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "gitlabcontainerscan":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "npmaudit":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "nodejsscan":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "semgrepscan":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "tfsec":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "whitesource":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "inspec":
            date_time = datetime.datetime.now()
            scan_dump = InspecScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "dockle":
            date_time = datetime.datetime.now()
            scan_dump = DockleScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
                    "project_id": project_id,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "openvas":
            date_time = datetime.datetime.now()
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
                    date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "nikto":
            date_time = datetime.datetime.now()
            scan_dump = NiktoResultDb(
                date_time=date_time,
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
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "twistlock":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        elif scanner == "brakeman":
            date_time = datetime.datetime.now()
            scan_dump = StaticScansDb(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
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
            return Response(
                {
                    "message": "Scan Data Uploaded",
                    "project_id": project_id,
                    "scan_id": scan_id,
                    "scanner": scanner,
                }
            )

        return Response({"message": "Scan Data Uploaded"})


class APIKey(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        user = request.user

        all_active_keys = OrgAPIKey.objects.filter(
            is_active=True
        )

        serialized_data = OrgAPIKeySerializer(all_active_keys, many=True)
        return Response(serialized_data.data, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user
        current_org = user.organization

        api_key = self.generate_api_key(user)

        new_api_key = OrgAPIKey.objects.create(
            api_key=api_key, created_by=user
        )

        content = {"APIKey": api_key, "id": new_api_key.uu_id}
        return Response(content, status=status.HTTP_200_OK)

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
