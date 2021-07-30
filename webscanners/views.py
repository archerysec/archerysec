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

from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from jiraticketing.models import jirasetting
from user_management import permissions
from webscanners.models import WebScanResultsDb, WebScansDb


class WebScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        all_scans = WebScansDb.objects.all()
        all_notify = Notification.objects.unread()
        return Response({"all_scans": all_scans, "message": all_notify})


class WebScanVulnInfo(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_url = None

        jira = jirasetting.objects.all()
        for d in jira:
            jira_url = d.jira_server

        scan_id = request.GET["scan_id"]
        name = request.GET["scan_name"]

        vuln_data = WebScanResultsDb.objects.filter(title=name, scan_id=scan_id)

        return render(
            request,
            "webscanners/scans/list_vuln_info.html",
            {"vuln_data": vuln_data, "jira_url": jira_url},
        )


class WebScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        vuln_name = request.POST.get("vuln_name")
        WebScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id).update(
            false_positive=false_positive, vuln_status=status
        )

        if false_positive == "Yes":
            vuln_info = WebScanResultsDb.objects.filter(
                scan_id=scan_id, vuln_id=vuln_id
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.url
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                WebScanResultsDb.objects.filter(
                    vuln_id=vuln_id, scan_id=scan_id
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                )

        all_vuln = WebScanResultsDb.objects.filter(
            scan_id=scan_id, false_positive="No", vuln_status="Open"
        )

        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info

        WebScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln_info")
            + "?scan_id=%s&scan_name=%s" % (scan_id, vuln_name)
        )


class WebScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        vuln_id = request.GET["vuln_id"]

        vul_dat = WebScanResultsDb.objects.filter(vuln_id=vuln_id).order_by("vuln_id")

        return render(
            request, "webscanners/scans/vuln_details.html", {"vul_dat": vul_dat}
        )


class WebScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = WebScansDb.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = WebScanResultsDb.objects.filter(scan_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


class WebScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = WebScanResultsDb.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        all_vuln = WebScanResultsDb.objects.filter(scan_id=scan_id)

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Information"))

        WebScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln") + "?scan_id=%s" % (scan_id)
        )


class WebScanVulnList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        all_vuln = WebScanResultsDb.objects.filter(scan_id=scan_id)
        return render(
            request,
            "webscanners/scans/list_vuln.html",
            {
                "all_vuln": all_vuln,
                "scan_id": scan_id,
            },
        )
