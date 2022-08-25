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

from django.core import signing
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from notifications.signals import notify
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView
from rest_framework import status

from jiraticketing.models import jirasetting
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management import permissions
from rest_framework.response import Response
from staticscanners.serializers import StaticScanDbSerializer, StaticScanResultsDbSerializer


class SastScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        scan_list = StaticScansDb.objects.filter()
        all_notify = Notification.objects.unread()

        if request.path[: 4] == '/api':
            serialized_data = StaticScanDbSerializer(scan_list, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "staticscanners/scans/list_scans.html",
                {"all_scans": scan_list, "message": all_notify},
            )


class SastScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        jira_url = None
        jira = jirasetting.objects.all()
        for d in jira:
            jira_url = d.jira_server

        all_notify = Notification.objects.unread()
        if uu_id == None:
            scan_id = request.GET["scan_id"]
            scan_name = request.GET["scan_name"]
            vuln_data = StaticScanResultsDb.objects.filter(scan_id=scan_id, title=scan_name)
        else:
            try:
                vuln_data = StaticScanResultsDb.objects.filter(scan_id=uu_id)
            except:
                return Response(
                    {"message": "Scan Id Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        if request.path[: 4] == '/api':
            serialized_data = StaticScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data)
        else:
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
        notes = request.POST.get("note")
        StaticScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id).update(
            false_positive=false_positive, vuln_status=status, note=notes
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
                    note=notes
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
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]
        jira_setting = jirasetting.objects.filter()
        user = request.user

        for jira in jira_setting:
            jira_server = jira.jira_server
            jira_username = jira.jira_username
            jira_password = jira.jira_password

        if jira_username is None:
            jira_username = None
        else:
            jira_username = signing.loads(jira_username)

        if jira_password is None:
            jira_password = None
        else:
            jira_password = signing.loads(jira_password)

        options = {"server": jira_server}
        try:
            jira_ser = JIRA(
                options, basic_auth=(jira_username, jira_password), max_retries=0
            )
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            jira_projects = None
            # notify.send(user, recipient=user, verb="Jira settings not found")

        vul_dat = StaticScanResultsDb.objects.filter(vuln_id=vuln_id).order_by(
            "vuln_id"
        )

        return render(
            request,
            "staticscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
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
        all_vuln = StaticScanResultsDb.objects.filter(scan_id=scan_id).distinct().values('title',
                                                                                         'severity',
                                                                                         'vuln_status',
                                                                                         'severity_color',
                                                                                         'scanner',
                                                                                         'note',
                                                                                         'scan_id').exclude(vuln_status='Duplicate')

        return render(
            request,
            "staticscanners/scans/list_vuln.html",
            {
                "all_vuln": all_vuln,
                "scan_id": scan_id,
            },
        )
