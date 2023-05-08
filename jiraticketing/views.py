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

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import uuid

from django.contrib import messages
from django.core import signing
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from jira import JIRA
from notifications.signals import notify
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from archerysettings.models import SettingsDb
from jiraticketing.models import jirasetting
from networkscanners.models import NetworkScanResultsDb
from staticscanners.models import StaticScanResultsDb
from user_management import permissions
from webscanners.models import WebScanResultsDb
from cloudscanners.models import CloudScansResultsDb


class JiraSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        jira_server = ""
        jira_username = ""
        jira_password = ""

        all_jira_settings = jirasetting.objects.filter(organization=request.user.organization)
        for jira in all_jira_settings:
            jira_server = jira.jira_server
            jira_username = signing.loads(jira.jira_username)
            jira_password = signing.loads(jira.jira_password)

        return render(
            request,
            "jiraticketing/jira_setting_form.html",
            {
                "jira_server": jira_server,
                "jira_username": jira_username,
                "jira_password": jira_password,
            },
        )

    def post(self, request):
        all_jira_settings = jirasetting.objects.filter(organization=request.user.organization)
        jira_server = ""
        for jira in all_jira_settings:
            jira_server = jira.jira_server

        setting_id = uuid.uuid4()
        jira_url = request.POST.get("jira_url")
        jira_username = request.POST.get("jira_username")
        jira_password = request.POST.get("jira_password")

        j_username = signing.dumps(jira_username)
        password = signing.dumps(jira_password)

        setting_dat = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Jira",
            organization=request.user.organization
        )
        setting_dat.save()

        save_data = jirasetting(
            setting_id=setting_id,
            jira_server=jira_url,
            jira_username=j_username,
            jira_password=password,
            organization=request.user.organization
        )
        save_data.save()

        options = {"server": jira_server}
        try:

            if jira_username is not None and jira_username != "" :
                jira_ser = JIRA(
                    options, basic_auth=(jira_username, jira_password), max_retries=0, timeout=30
                )
            else :
                jira_ser = JIRA(options, token_auth=jira_password, max_retries=0, timeout=30)
            jira_projects = jira_ser.projects()
            print(len(jira_projects))
            jira_info = True
            SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                setting_status=jira_info
            )
        except Exception as e:
            print(e)
            jira_info = False
            SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                setting_status=jira_info
            )

        return HttpResponseRedirect(reverse("archerysettings:settings"))


class CreateJiraTicket(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        jira_setting = jirasetting.objects.filter(organization=request.user.organization)
        user = request.user
        jira_server = ""
        jira_username = None
        jira_password = None
        jira_projects = ""

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
                    options, basic_auth=(jira_username, jira_password), max_retries=0, timeout=30
                )
            else :
                jira_ser = JIRA(options, token_auth=jira_password, max_retries=0, timeout=30)
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb="Jira settings not found")

        summary = request.GET["summary"]
        description = request.GET["description"]
        scanner = request.GET["scanner"]
        vuln_id = request.GET["vuln_id"]
        scan_id = request.GET["scan_id"]

        return render(
            request,
            "jiraticketing/submit_jira_ticket.html",
            {
                "jira_projects": jira_projects,
                "summary": summary,
                "description": description,
                "scanner": scanner,
                "vuln_id": vuln_id,
                "scan_id": scan_id,
            },
        )

    def post(self, request):
        jira_setting = jirasetting.objects.filter(organization=request.user.organization)
        user = request.user

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
            # jira_projects =
            jira_ser.projects()
        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb="Jira settings not found")
        summary = request.POST.get("summary")
        description = request.POST.get("description")
        project_id = request.POST.get("project_id")
        issue_type = request.POST.get("issue_type")
        vuln_id = request.POST.get("vuln_id")
        scanner = request.POST.get("scanner")
        scan_id = request.POST.get("scan_id")

        issue_dict = {
            "project": {"id": project_id},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
        new_issue = jira_ser.create_issue(fields=issue_dict)

        if scanner == "web":
            WebScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=new_issue
            )
            messages.success(request, "Jira Ticket Submitted ID: %s", new_issue)
            return HttpResponseRedirect(
                reverse("webscanners:list_vuln_info")
                + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
            )

        elif scanner == "sast":
            StaticScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=new_issue
            )
            messages.success(request, "Jira Ticket Submitted ID: %s", new_issue)
            return HttpResponseRedirect(
                reverse("staticscanners:list_vuln_info")
                + "?scan_id=%s&test_name=%s" % (scan_id, summary)
            )

        elif scanner == "network":
            NetworkScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=new_issue
            )
            ip = (
                NetworkScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization)
                .values("ip")
                .get()["ip"]
            )

            messages.success(request, "Jira Ticket Submitted ID: %s", new_issue)
            return HttpResponseRedirect(
                reverse("networkscanners:list_vuln_info")
                + "?scan_id=%s&ip=%s" % (scan_id, ip)
            )
        elif scanner == "cloud":
            CloudScansResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=new_issue
            )

            messages.success(request, "Jira Ticket Submitted ID: %s", new_issue)
            return HttpResponseRedirect(
                reverse("cloudscanners:list_vuln") + "?scan_id=%s" % (scan_id)
            )


class LinkJiraTicket(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        jira_setting = jirasetting.objects.filter(organization=request.user.organization)
        user = request.user
        jira_server = ""
        jira_username = None
        jira_password = None
        jira_projects = ""

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
                    options, basic_auth=(jira_username, jira_password), max_retries=0, timeout=30
                )
            else :
                jira_ser = JIRA(options, token_auth=jira_password, max_retries=0, timeout=30)
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb="Jira settings not found")

        summary = request.GET.get("summary", "Not found")
        jira_tick_id = request.GET.get("jira_tick_id", "Not found")
        scanner = request.GET.get("scanner", "Not found")
        vuln_id = request.GET.get("vuln_id", "Not found")
        scan_id = request.GET.get("scan_id", "Not found")

        return render(
            request,
            "jiraticketing/link_jira_ticket.html",
            {
                "jira_projects": jira_projects,
                "summary": summary,
                "jira_tick_id": jira_tick_id,
                "scanner": scanner,
                "vuln_id": vuln_id,
                "scan_id": scan_id,
            },
        )

    def post(self, request):
        jira_setting = jirasetting.objects.filter(organization=request.user.organization)
        user = request.user

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
            if jira_username is not None and jira_username != "":
                jira_ser = JIRA(
                    options, basic_auth=(jira_username, jira_password), timeout=30
                )
            else :
                jira_ser = JIRA(options, token_auth=jira_password, timeout=30)
        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb="Jira settings not found")

        summary = request.POST.get("summary")
        jira_tick_id = request.POST.get("jira_tick_id")
        current_jira_ticket_id = request.POST.get("current_jira_ticket_id")
        vuln_id = request.POST.get("vuln_id")
        scanner = request.POST.get("scanner", "Not found")
        scan_id = request.POST.get("scan_id")

        if current_jira_ticket_id is None:
            messages.warning(request, "Current Jira Ticket not Found")

        # If blank ticket ID, set the Jira Ticket to None in the database
        linked_issue = None
        if jira_tick_id is not None and jira_tick_id.strip() != "":
            try:
                linked_issue = current_jira_ticket_id
                jira_ser.create_issue_link(type="duplicates", inwardIssue=current_jira_ticket_id, outwardIssue=jira_tick_id)
            except Exception as e:
                print(e)
                messages.warning(request, "Jira Ticket not found")
                if scanner == "web":
                    return HttpResponseRedirect(
                        reverse("webscanners:list_vuln_info")
                        + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
                    )
                elif scanner == "sast":
                    return HttpResponseRedirect(
                        reverse("staticscanners:list_vuln_info")
                        + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
                    )
                elif scanner == "network":
                    ip = (
                        NetworkScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization)
                        .values("ip")
                        .get()["ip"]
                    )
                    return HttpResponseRedirect(
                        reverse("networkscanners:list_vuln_info")
                        + "?scan_id=%s&ip=%s" % (scan_id, ip)
                    )
                elif scanner == "cloud":
                    return HttpResponseRedirect(
                        reverse("cloudscanners:list_vuln_info")
                        + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
                    )
                else:
                    return HttpResponseRedirect(reverse("dashboard:dashboard"))

        if scanner == "web":
            WebScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=linked_issue
            )
            messages.success(request, "Jira Ticket Linked ID: %s" % linked_issue)
            return HttpResponseRedirect(
                reverse("webscanners:list_vuln_info")
                + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
            )

        elif scanner == "sast":
            StaticScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=linked_issue
            )
            messages.success(request, "Jira Ticket Linked ID: %s" % linked_issue)
            return HttpResponseRedirect(
                reverse("staticscanners:list_vuln_info")
                + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
            )

        elif scanner == "network":
            NetworkScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=linked_issue
            )
            ip = (
                NetworkScanResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization)
                .values("ip")
                .get()["ip"]
            )

            messages.success(request, "Jira Ticket Linked ID: %s" % linked_issue)
            return HttpResponseRedirect(
                reverse("networkscanners:list_vuln_info")
                + "?scan_id=%s&ip=%s" % (scan_id, ip)
            )

        elif scanner == "cloud":
            CloudScansResultsDb.objects.filter(vuln_id=vuln_id, organization=request.user.organization).update(
                jira_ticket=linked_issue
            )

            messages.success(request, "Jira Ticket Linked ID: %s" % linked_issue)
            return HttpResponseRedirect(
                reverse("cloudscanners:list_vuln_info")
                + "?scan_id=%s&scan_name=%s" % (scan_id, summary)
            )

        # Scanner not found
        else:
            messages.warning(request, "Invalid scanner type")
            return HttpResponseRedirect(reverse("dashboard:dashboard"))
