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

from __future__ import unicode_literals

import hashlib
import json
import uuid
from datetime import datetime

from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from compliance.models import DockleScanDb, InspecScanDb
from jiraticketing.models import jirasetting
from projects.models import ProjectDb
from scanners.scanner_parser.compliance_parser.dockle_json_parser import \
    dockle_report_json
from scanners.scanner_parser.compliance_parser.inspec_json_parser import \
    inspec_report_json
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import \
    bandit_report_json
from scanners.scanner_parser.staticscanner_parser.brakeman_json_report_parser import \
    brakeman_report_json
from scanners.scanner_parser.staticscanner_parser.clair_json_report_parser import \
    clair_report_json
from scanners.scanner_parser.staticscanner_parser.gitlab_container_json_report_parser import \
    gitlabcontainerscan_report_json
from scanners.scanner_parser.staticscanner_parser.gitlab_sast_json_report_parser import \
    gitlabsast_report_json
from scanners.scanner_parser.staticscanner_parser.gitlab_sca_json_report_parser import \
    gitlabsca_report_json
from scanners.scanner_parser.staticscanner_parser.nodejsscan_report_json import \
    nodejsscan_report_json
from scanners.scanner_parser.staticscanner_parser.npm_audit_report_json import \
    npmaudit_report_json
from scanners.scanner_parser.staticscanner_parser.retirejss_json_parser import \
    retirejs_report_json
from scanners.scanner_parser.staticscanner_parser.semgrep_json_report_parser import \
    semgrep_report_json
from scanners.scanner_parser.staticscanner_parser.tfsec_report_parser import \
    tfsec_report_json
from scanners.scanner_parser.staticscanner_parser.trivy_json_report_parser import \
    trivy_report_json
from scanners.scanner_parser.staticscanner_parser.twistlock_json_report_parser import \
    twistlock_report_json
from scanners.scanner_parser.staticscanner_parser.whitesource_json_report_parser import \
    whitesource_report_json
# from staticscanners.models import <scannername>_scan_db
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management import permissions


def upload(project_name, scan_id, date_time, project_id, scan_status, scanner, data):
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
        project_name=project_name,
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


class SastScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_list = StaticScansDb.objects.filter()

        all_notify = Notification.objects.unread()

        return render(
            request,
            "staticscanners/scans/list_scans.html",
            {"all_scans": scan_list, "message": all_notify},
        )


class SastScanVulnInfo(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_url = None
        jira = jirasetting.objects.all()
        for d in jira:
            jira_url = d.jira_server
        scan_id = request.GET["scan_id"]
        name = request.GET["scan_name"]
        vuln_data = StaticScanResultsDb.objects.filter(title=name, scan_id=scan_id)
        return render(
            request,
            "staticscanners/scans/list_vuln_info.html",
            {"vuln_data": vuln_data, "jira_url": jira_url},
        )


class SastScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        vuln_name = request.POST.get("vuln_name")
        StaticScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id).update(
            false_positive=false_positive, vuln_status=status
        )

        if false_positive == "Yes":
            vuln_info = StaticScanResultsDb.objects.filter(
                scan_id=scan_id, vuln_id=vuln_id
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.fileName
                severity = vi.severity
                dup_data = str(name) + str(url) + str(severity)
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                StaticScanResultsDb.objects.filter(
                    vuln_id=vuln_id, scan_id=scan_id
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                )

        all_vuln = StaticScanResultsDb.objects.filter(
            scan_id=scan_id, false_positive="No", vuln_status="Open"
        )

        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info

        StaticScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
        )
        return HttpResponseRedirect(
            reverse("staticscanners:list_vuln_info")
            + "?scan_id=%s&scan_name=%s" % (scan_id, vuln_name)
        )


class SastScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        vuln_id = request.GET["vuln_id"]
        vul_dat = StaticScanResultsDb.objects.filter(vuln_id=vuln_id).order_by(
            "vuln_id"
        )

        return render(
            request, "staticscanners/scans/vuln_details.html", {"vul_dat": vul_dat}
        )


class SastScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_scans.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst,
    )

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = StaticScansDb.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = StaticScanResultsDb.objects.filter(scan_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse("staticscanners:list_scans"))


class SastScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = StaticScanResultsDb.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        all_vuln = StaticScanResultsDb.objects.filter(scan_id=scan_id)

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Information"))

        StaticScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
        )
        return HttpResponseRedirect(
            reverse("staticscanners:list_vuln") + "?scan_id=%s" % (scan_id)
        )


class SastScanVulnList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/scans/list_vuln.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        all_vuln = StaticScanResultsDb.objects.filter(scan_id=scan_id)

        return render(
            request,
            "staticscanners/scans/list_vuln.html",
            {
                "all_vuln": all_vuln,
                "scan_id": scan_id,
            },
        )


class UploadJSONReport(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "staticscanners/report_import.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_project = ProjectDb.objects.filter()

        return render(
            request, "staticscanners/report_import.html", {"all_project": all_project}
        )

    def post(self, request):
        all_project = ProjectDb.objects.filter()
        project_uu_id = request.POST.get("project_id")
        project_id = (
            ProjectDb.objects.filter(uu_id=project_uu_id).values("id").get()["id"]
        )
        scanner = request.POST.get("scanner")
        json_file = request.FILES["jsonfile"]
        project_name = request.POST.get("project_name")
        scan_id = uuid.uuid4()
        scan_status = "100"

        if scanner == "bandit_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Bandit"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "retirejs_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Retirejs"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "clair_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Clair"

                upload(
                    project_name,
                    scan_id,
                    date_time,
                    project_id,
                    scan_status,
                    scanner,
                    data,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("staticscanners:list_scanss"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(
                    request,
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "trivy_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Trivy"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "npmaudit_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Npmaudit"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "nodejsscan_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Nodejsscan"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "semgrepscan_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Semgrep"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "tfsec_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Tfsec"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "whitesource_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Whitesource"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "inspec_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scan_dump = InspecScanDb(
                    project_name=project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "dockle_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scan_dump = DockleScanDb(
                    project_name=project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabsast_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Gitlabsast"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabcontainerscan_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Gitlabcontainerscan"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "gitlabsca_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Gitlabsca"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "twistlock_scan":
            try:
                date_time = datetime.now()

                j = json_file.read()
                data = json.loads(j)
                scanner = "Twistlock"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )

        if scanner == "brakeman_scan":
            try:
                date_time = datetime.now()
                j = json_file.read()
                data = json.loads(j)
                scanner = "Brakeman_scan"

                upload(
                    project_name,
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
                    "staticscanners/report_import.html",
                    {"all_project": all_project},
                )
