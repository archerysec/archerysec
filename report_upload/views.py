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

import defusedxml.ElementTree as ET
from lxml import etree
import os

from scanners.scanner_parser.staticscanner_parser import (
    checkmarx_xml_report_parser,
    dependencycheck_report_parser,
    findbugs_report_parser,
)
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from scanners.scanner_parser.web_scanner import (
    acunetix_xml_parser,
    arachni_xml_parser,
    burp_xml_parser,
    netsparker_xml_parser,
    webinspect_xml_parser,
    zap_xml_parser,
)
from scanners.scanner_parser.network_scanner import (
    Nessus_Parser,
    OpenVas_Parser,
    nmap_parser,
)
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb, TaskScheduleDb
from tools.models import NiktoResultDb
from webscanners.models import WebScansDb
from rest_framework.parsers import FormParser, MultiPartParser
from scanners.scanner_parser.compliance_parser.dockle_json_parser import (
    dockle_report_json,
)
from scanners.scanner_parser.compliance_parser.inspec_json_parser import (
    inspec_report_json,
)
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import (
    bandit_report_json,
)
from scanners.scanner_parser.staticscanner_parser.brakeman_json_report_parser import (
    brakeman_report_json,
)
from scanners.scanner_parser.staticscanner_parser.clair_json_report_parser import (
    clair_report_json,
)
from scanners.scanner_parser.staticscanner_parser.gitlab_container_json_report_parser import (
    gitlabcontainerscan_report_json,
)
from scanners.scanner_parser.staticscanner_parser.gitlab_sast_json_report_parser import (
    gitlabsast_report_json,
)
from scanners.scanner_parser.staticscanner_parser.gitlab_sca_json_report_parser import (
    gitlabsca_report_json,
)
from scanners.scanner_parser.staticscanner_parser.nodejsscan_report_json import (
    nodejsscan_report_json,
)
from scanners.scanner_parser.staticscanner_parser.npm_audit_report_json import (
    npmaudit_report_json,
)
from scanners.scanner_parser.staticscanner_parser.retirejss_json_parser import (
    retirejs_report_json,
)
from scanners.scanner_parser.staticscanner_parser.semgrep_json_report_parser import (
    semgrep_report_json,
)
from scanners.scanner_parser.staticscanner_parser.tfsec_report_parser import (
    tfsec_report_json,
)
from scanners.scanner_parser.staticscanner_parser.trivy_json_report_parser import (
    trivy_report_json,
)
from scanners.scanner_parser.staticscanner_parser.twistlock_json_report_parser import (
    twistlock_report_json,
)
from scanners.scanner_parser.staticscanner_parser.whitesource_json_report_parser import (
    whitesource_report_json,
)

import hashlib
import json
import uuid
from datetime import datetime

from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from compliance.models import DockleScanDb, InspecScanDb
from projects.models import ProjectDb

from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management import permissions


def upload(target, scan_id, date_time, project_id, scan_status, scanner, data):
    """

    :param project_name:
    :param scan_id:
    :param date_time:
    :param project_id:
    :param scan_status:
    :param scanner:
    :param username:
    :param data:
    :return:
    """
    scan_dump = StaticScansDb(
        project_name=target,
        scan_id=scan_id,
        date_time=date_time,
        project_id=project_id,
        scan_status=scan_status,
        scanner=scanner,
    )
    scan_dump.save()

    if scanner == "Bandit":
        bandit_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Retirejs":
        retirejs_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Clair":
        clair_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Trivy":
        trivy_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Npmaudit":
        npmaudit_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Nodejsscan":
        nodejsscan_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Semgrep":
        semgrep_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Tfsec":
        tfsec_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Whitesource":
        whitesource_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Gitlabsast":
        gitlabsast_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Gitlabcontainerscan":
        gitlabcontainerscan_report_json(
            data=data, project_id=project_id, scan_id=scan_id
        )
    elif scanner == "Gitlabsca":
        gitlabsast_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Gitlabsca":
        gitlabsca_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Twistlock":
        twistlock_report_json(data=data, project_id=project_id, scan_id=scan_id)
    elif scanner == "Brakeman_scan":
        brakeman_report_json(data=data, project_id=project_id, scan_id=scan_id)


class Upload(APIView):
    parser_classes = (MultiPartParser,)
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "report_upload/upload.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def check_file_ext(self, file):
        split_tup = os.path.splitext(file)
        file_extension = split_tup[1]
        return file_extension

    def get(self, request):
        all_project = ProjectDb.objects.filter()

        return render(
            request, "report_upload/upload.html", {"all_project": all_project}
        )

    def post(self, request):
        all_project = ProjectDb.objects.filter()
        project_uu_id = request.POST.get("project_id")
        project_id = (
            ProjectDb.objects.filter(uu_id=project_uu_id).values("id").get()["id"]
        )
        scanner = request.POST.get("scanner")
        file = request.FILES["file"]
        target = request.POST.get("target")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "ZAP Scanner Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                tree = ET.parse(file)
                date_time = datetime.now()

                root_xml = tree.getroot()
                en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                    "ascii", "ignore"
                )
                root_xml_en = ET.fromstring(en_root_xml)
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    rescan="No",
                    scanner="Zap",
                )
                scan_dump.save()
                zap_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml_en,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "burp_scan":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Burp Scan Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()
                # Burp scan XML parser
                tree = ET.parse(file)
                root_xml = tree.getroot()
                en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                    "ascii", "ignore"
                )
                root_xml_en = ET.fromstring(en_root_xml)
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Burp",
                )
                scan_dump.save()
                burp_xml_parser.burp_scan_data(root_xml_en, project_id, scan_id)
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "arachni":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Arachni Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                tree = ET.parse(file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Arachni",
                )
                scan_dump.save()
                arachni_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                    target_url=target,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "netsparker":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Netsparker Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                tree = ET.parse(file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Netsparker",
                )
                scan_dump.save()
                netsparker_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )
        elif scanner == "webinspect":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Webinspect Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                tree = ET.parse(file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Webinspect",
                )
                scan_dump.save()
                webinspect_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "acunetix":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Acunetix Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                tree = ET.parse(file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scanner="Acunetix",
                    scan_status=scan_status,
                )
                scan_dump.save()
                acunetix_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "dependencycheck":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Dependencycheck Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                data = etree.parse(file)
                root = data.getroot()
                scan_dump = StaticScansDb(
                    project_name=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner="Dependencycheck",
                )
                scan_dump.save()
                dependencycheck_report_parser.xml_parser(
                    project_id=project_id, scan_id=scan_id, data=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "checkmarx":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Checkmarx Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                data = etree.parse(file)
                root = data.getroot()
                scan_dump = StaticScansDb(
                    project_name=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                )
                scan_dump.save()
                checkmarx_xml_report_parser.checkmarx_report_xml(
                    project_id=project_id, scan_id=scan_id, data=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "findbugs":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Findbugs Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                tree = ET.parse(file)
                root = tree.getroot()
                scan_dump = StaticScansDb(
                    project_name=target,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                )
                scan_dump.save()
                findbugs_report_parser.xml_parser(
                    project_id=project_id, scan_id=scan_id, root=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        elif scanner == "nikto":
            try:
                if self.check_file_ext(str(file)) != ".xml":
                    messages.error(request, "Nikto Only XML file Support")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()
                scan_dump = NiktoResultDb(
                    date_time=date_time,
                    scan_url=target,
                    scan_id=scan_id,
                    project_id=project_id,
                )
                scan_dump.save()

                nikto_html_parser(file, project_id, scan_id)
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("tools:nikto"))
            except:
                messages.error(request, "File Not Supported")
                return render(
                    request, "report_upload/upload.html", {"all_project": all_project}
                )

        if scanner == "bandit_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Bandit Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Bandit"

                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "retirejs_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Retirejs Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Retirejs"

                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "clair_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Clair Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Clair"

                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "trivy_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Trivy Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Trivy"

                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "npmaudit_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "NPM Audit Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Npmaudit"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "nodejsscan_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Nodejs scan Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Nodejsscan"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "semgrepscan_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Semgrep scan Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Semgrep"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "tfsec_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Tfsec Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Tfsec"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "whitesource_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Whitesource Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Whitesource"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "inspec_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Inspec Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scan_dump = InspecScanDb(
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                )
                scan_dump.save()
                inspec_report_json(
                    data=data,
                    project_id=project_id,
                    scan_id=scan_id,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("inspec:inspec_list"))
            except:
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "dockle_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Dockle Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scan_dump = DockleScanDb(

                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                )
                scan_dump.save()
                dockle_report_json(
                    data=data,
                    project_id=project_id,
                    scan_id=scan_id,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("dockle:dockle_list"))
            except:
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabsast_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Gitlabsast Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Gitlabsast"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabcontainerscan_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Gitlabcontainerscan Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Gitlabcontainerscan"

                upload(
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabsca_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Gitlabsca Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Gitlabsca"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "twistlock_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Twistlock Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()

                j = file.read()
                data = json.loads(j)
                scanner = "Twistlock"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "brakeman_scan":
            try:
                if self.check_file_ext(str(file)) != ".json":
                    messages.error(request, "Brakeman Only JSON file Supported")
                    return HttpResponseRedirect(reverse("report_upload:upload"))
                date_time = datetime.now()
                j = file.read()
                data = json.loads(j)
                scanner = "Brakeman_scan"
                upload(
                    target,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "report_upload/upload.html",
                    {"all_project": all_project},
                )

        if scanner == "openvas":
            if self.check_file_ext(str(file)) != ".xml":
                messages.error(request, "Openvas Only XML file Supported")
                return HttpResponseRedirect(reverse("report_upload:upload"))
            date_time = datetime.now()
            tree = ET.parse(file)
            root_xml = tree.getroot()
            hosts = OpenVas_Parser.get_hosts(root_xml)
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
                root=root_xml,
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))
        elif scanner == "nessus":
            if self.check_file_ext(str(file)) != ".nessus":
                messages.error(request, "Nessus Only nessus file Supported")
                return HttpResponseRedirect(reverse("report_upload:upload"))
            date_time = datetime.now()
            tree = ET.parse(file)
            root_xml = tree.getroot()
            Nessus_Parser.updated_nessus_parser(
                root=root_xml,
                scan_id=scan_id,
                project_id=project_id,
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))
        elif scanner == "nmap":
            tree = ET.parse(file)
            root_xml = tree.getroot()
            nmap_parser.xml_parser(
                root=root_xml,
                scan_id=scan_id,
                project_id=project_id,
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("tools:nmap_scan"))
