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
""" Author: Anand Tiwari """

from __future__ import unicode_literals

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.core import signing
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archerysettings import load_settings, save_settings
from archerysettings.models import EmailDb, SettingsDb
from jiraticketing.models import jirasetting
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb,
                                    TaskScheduleDb)
from networkscanners.serializers import (NetworkScanDbSerializer,
                                         NetworkScanResultsDbSerializer,
                                         OpenvasScansSerializer,
                                         OpenvasSettingsSerializer)
from projects.models import ProjectDb
from scanners.scanner_plugin.network_scanner.openvas_plugin import (
    OpenVAS_Plugin, vuln_an_id)
from user_management import permissions

api_data = os.getcwd() + "/" + "apidata.json"

# status = ""
name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
page = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""


def email_notify(user, subject, message):
    to_mail = ""
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        pass


def openvas_scanner(scan_ip, project_id, sel_profile, user, request):
    """
    The function is launch the OpenVAS scans.
    :param scan_ip:
    :param project_id:
    :param sel_profile:
    :return:
    """
    openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request)
    try:
        scanner = openvas.connect()
    except Exception:
        notify.send(user, recipient=user, verb="OpenVAS Setting not configured")
        subject = "Archery Tool Notification"
        message = "OpenVAS Scanner failed due to setting not found "

        email_notify(user=user, subject=subject, message=message)
        return

    notify.send(user, recipient=user, verb="OpenVAS Scan Started")
    subject = "Archery Tool Notification"
    message = "OpenVAS Scan Started"

    email_notify(user=user, subject=subject, message=message)
    scan_id, target_id = openvas.scan_launch(scanner)
    date_time = datetime.now()
    save_all = NetworkScanDb(
        scan_id=str(scan_id),
        project_id=str(project_id),
        ip=scan_ip,
        date_time=date_time,
        scan_status=0.0,
        scanner="Openvas",
    )
    save_all.save()
    openvas.scan_status(scanner=scanner, scan_id=scan_id)
    time.sleep(5)
    vuln_an_id(scan_id=scan_id, project_id=project_id, request=request)

    notify.send(user, recipient=user, verb="OpenVAS Scan Completed")

    all_openvas = NetworkScanDb.objects.filter()
    all_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for openvas in all_openvas:
        all_vuln = openvas.total_vul
        total_high = openvas.high_vul
        total_medium = openvas.medium_vul
        total_low = openvas.low_vul

    subject = "Archery Tool Notification"
    message = (
        "OpenVAS Scan Completed  <br>"
        "Total: %s  <br>Total High: %s <br>"
        "Total Medium: %s  <br>Total Low %s"
        % (all_vuln, total_high, total_medium, total_low)
    )

    email_notify(user=user, subject=subject, message=message)

    return HttpResponse(status=201)


class OpenvasLaunchScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_ip = NetworkScanDb.objects.filter(organization=request.user.organization)

        return render("networkscanners/openvas_vuln_list.html", {"all_ip": all_ip})

    def post(self, request):
        user = request.user
        if request.path[:4] == "/api":
            serializer = OpenvasScansSerializer(data=request.data)
            if serializer.is_valid():
                scan_ip = request.data.get(
                    "scan_ip",
                )

                project_uu_id = request.data.get(
                    "project_id",
                )
            else:
                return Response({"message": "Invalid data"})
        else:
            scan_ip = request.POST.get("ip")
            project_uu_id = request.POST.get("project_id")
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id, organization=request.user.organization
            )
            .values("id")
            .get()["id"]
        )
        sel_profile = request.POST.get("scan_profile")
        ip = scan_ip.replace(" ", "")
        target_split = ip.split(",")
        split_length = target_split.__len__()

        print(split_length)

        for i in range(0, split_length):
            target = target_split.__getitem__(i)

            thread = threading.Thread(
                target=openvas_scanner,
                args=(target, project_id, sel_profile, user, request),
            )
            thread.daemon = True
            thread.start()

        if request.path[:4] == "/api":
            return Response({"message": "Openvas scan launched"})
        else:
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScan(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/ipscan.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_scans = NetworkScanDb.objects.filter(organization=request.user.organization)
        all_proj = ProjectDb.objects.filter(organization=request.user.organization)

        all_notify = Notification.objects.unread()

        return render(
            request,
            "networkscanners/ipscan.html",
            {
                "all_scans": all_scans,
                "all_proj": all_proj,
                "message": all_notify,
            },
        )


class OpenvasDetails(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(
            request,
            "networkscanners/setting_form.html",
        )

    def post(self, request):
        setting_id = uuid.uuid4()
        save_openvas_setting = save_settings.SaveSettings(
            api_data,
        )

        if request.POST.get("openvas_enabled") == "on":
            openvas_enabled = True
        else:
            openvas_enabled = False

        if request.path[:4] == "/api":
            serializer = OpenvasSettingsSerializer(data=request.data)
            if serializer.is_valid():
                openvas_host = request.data.get(
                    "openvas_host",
                )
                openvas_port = request.data.get(
                    "openvas_port",
                )
                openvas_user = request.data.get(
                    "openvas_user",
                )
                openvas_password = request.data.get(
                    "openvas_password",
                )
                openvas_enabled = request.data.get(
                    "openvas_enabled",
                )
            else:
                return Response({"message": "Invalid Data"})
        else:
            openvas_host = request.POST.get("openvas_host")
            openvas_port = request.POST.get("openvas_port")
            openvas_user = request.POST.get("openvas_user")
            openvas_password = request.POST.get("openvas_password")

        save_openvas_setting.openvas_settings(
            openvas_host=openvas_host,
            openvas_port=openvas_port,
            openvas_enabled=openvas_enabled,
            openvas_user=openvas_user,
            openvas_password=openvas_password,
            setting_id=setting_id,
        )

        save_settings_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Openvas",
            organization=request.user.organization,
        )
        save_settings_data.save()

        sel_profile = ""

        openvas = OpenVAS_Plugin(
            openvas_host,
            setting_id,
            sel_profile,
        )
        try:
            openvas.connect()
            openvas_info = True
            SettingsDb.objects.filter(
                setting_id=setting_id, organization=request.user.organization
            ).update(setting_status=openvas_info)
        except Exception:
            openvas_info = False
            SettingsDb.objects.filter(
                setting_id=setting_id, organization=request.user.organization
            ).update(setting_status=openvas_info)
            if request.path[:4] == "/api":
                return Response({"message": "Openvas Not Working"})

        if request.path[:4] == "/api":
            return Response(
                {
                    "message": "Openvas Scanner setting updated !!!",
                }
            )
        else:
            return HttpResponseRedirect(reverse("archerysettings:settings"))


class OpenvasSetting(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        load_openvas_setting = load_settings.ArcherySettings(
            api_data,
        )
        openvas_host = load_openvas_setting.openvas_host()
        openvas_port = load_openvas_setting.openvas_port()
        openvas_enabled = load_openvas_setting.openvas_enabled()
        if openvas_enabled:
            openvas_enabled = "True"
        else:
            openvas_enabled = "False"
        openvas_user = load_openvas_setting.openvas_username()
        openvas_password = load_openvas_setting.openvas_pass()
        if request.path[:4] == "/api":
            return Response(
                {
                    "openvas_host": openvas_host,
                    "openvas_port": openvas_port,
                    "openvas_enabled": openvas_enabled,
                    "openvas_user": openvas_user,
                    "openvas_password": openvas_password,
                }
            )
        else:
            return render(
                request,
                "networkscanners/setting_form.html",
                {
                    "openvas_host": openvas_host,
                    "openvas_port": openvas_port,
                    "openvas_enabled": openvas_enabled,
                    "openvas_user": openvas_user,
                    "openvas_password": openvas_password,
                },
            )



class NetworkScanSchedule(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/network_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        # task_id = ""

        all_scans_db = ProjectDb.objects.filter(organization=request.user.organization)
        all_scheduled_scans = TaskScheduleDb.objects.filter(
            organization=request.user.organization
        )
        return render(
            request,
            "networkscanners/network_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )

    def post(self, request):
        scan_ip = request.POST.get("ip")
        scan_schedule_time = request.POST.get("datetime")
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        periodic_task_value = request.POST.get("periodic_task_value")

        if periodic_task_value == "HOURLY":
            periodic_time = Task.HOURLY
        elif periodic_task_value == "DAILY":
            periodic_time = Task.DAILY
        elif periodic_task_value == "WEEKLY":
            periodic_time = Task.WEEKLY
        elif periodic_task_value == "EVERY_2_WEEKS":
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == "EVERY_4_WEEKS":
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None

        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y %H:%M:%S %p")

        # task(scan_ip, project_id, schedule=dt_obj)
        ip = scan_ip.replace(" ", "")
        target__split = ip.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == "open_vas":
                if periodic_task_value == "None":
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id
                else:
                    my_task = task(
                        target,
                        project_id,
                        scanner,
                        repeat=periodic_time,
                        repeat_until=None,
                    )
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id

            save_scheadule = TaskScheduleDb(
                task_id=task_id,
                target=target,
                schedule_time=scan_schedule_time,
                project_id=project_id,
                scanner=scanner,
                periodic_task=periodic_task_value,
            )
            save_scheadule.save()


class NetworkScanScheduleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/network_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = TaskScheduleDb.objects.filter(
                task_id=task_id, organization=request.user.organization
            )
            del_task.delete()
            del_task_schedule = Task.objects.filter(
                id=task_id, organization=request.user.organization
            )
            del_task_schedule.delete()

        return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))


class OpenvasSettingEnable(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/nv_settings.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        load_nv_setting = load_settings.ArcherySettings(
            api_data,
        )
        nv_enabled = str(load_nv_setting.nv_enabled())
        nv_online = str(load_nv_setting.nv_enabled())
        nv_version = str(load_nv_setting.nv_enabled())
        nv_timing = load_nv_setting.nv_timing()

        return render(
            request,
            "networkscanners/nv_settings.html",
            {
                "nv_enabled": nv_enabled,
                "nv_online": nv_online,
                "nv_version": nv_version,
                "nv_timing": nv_timing,
            },
        )


class OpenvasSettingEnableDetails(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/nv_settings.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(
            request,
            "networkscanners/nv_settings.html",
            {
                "messages": messages,
            },
        )

    def post(self, request):
        save_nv_setting = save_settings.SaveSettings(
            api_data,
        )
        if str(request.POST.get("nv_enabled")) == "on":
            nv_enabled = True
        else:
            nv_enabled = False
        if str(request.POST.get("nv_online")) == "on":
            nv_online = True
        else:
            nv_online = False
        if str(request.POST.get("nv_version")) == "on":
            nv_version = True
        else:
            nv_version = False
        nv_timing = int(str(request.POST.get("nv_timing")))
        if nv_timing > 5:
            nv_timing = 5
        elif nv_timing < 0:
            nv_timing = 0

        save_nv_setting.nmap_vulners(
            enabled=nv_enabled, version=nv_version, online=nv_online, timing=nv_timing
        )

        return HttpResponseRedirect(reverse("archerysettings:settings"))


class NetworkScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        scan_list = NetworkScanDb.objects.filter(organization=request.user.organization)
        all_notify = Notification.objects.unread()
        if request.path[:4] == "/api":
            serialized_data = NetworkScanDbSerializer(scan_list, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "networkscanners/scans/list_scans.html",
                {"all_scans": scan_list, "message": all_notify},
            )


class NetworkScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        jira_url = None
        jira = jirasetting.objects.filter(organization=request.user.organization)
        for d in jira:
            jira_url = d.jira_server
        if uu_id is None:
            scan_id = request.GET["scan_id"]
            ip = request.GET["ip"]
            vuln_data = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, ip=ip, organization=request.user.organization
            )
        else:
            try:
                vuln_data = NetworkScanResultsDb.objects.filter(
                    scan_id=uu_id, organization=request.user.organization
                )
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        if request.path[:4] == "/api":
            serialized_data = NetworkScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "networkscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url},
            )


class NetworkScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")
        ip = request.POST.get("ip")
        notes = request.POST.get("note")
        NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id,
            scan_id=scan_id,
            scanner=scanner,
            organization=request.user.organization,
        ).update(false_positive=false_positive, vuln_status=status, note=notes)

        if false_positive == "Yes":
            vuln_info = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id,
                vuln_id=vuln_id,
                scanner=scanner,
                organization=request.user.organization,
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.ip
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                NetworkScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id,
                    scanner=scanner,
                    organization=request.user.organization,
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                    note=notes,
                )

        all_vuln = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
            vuln_status="Open",
            scanner=scanner,
            organization=request.user.organization,
        )

        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info

        NetworkScanDb.objects.filter(
            scan_id=scan_id, scanner=scanner, organization=request.user.organization
        ).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
        )
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln_info")
            + "?scan_id=%s&ip=%s&scanner=%s" % (scan_id, ip, scanner)
        )


class NetworkScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]
        scanner = request.GET["scanner"]
        jira_setting = jirasetting.objects.filter(
            organization=request.user.organization
        )
        # user = request.user

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
                    options,
                    basic_auth=(jira_username, jira_password),
                    max_retries=0,
                    timeout=30,
                )
            else:
                jira_ser = JIRA(
                    options, token_auth=jira_password, max_retries=0, timeout=30
                )
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            jira_projects = None
            # notify.send(user, recipient=user, verb="Jira settings not found")

        vul_dat = NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id, scanner=scanner, organization=request.user.organization
        ).order_by("vuln_id")

        return render(
            request,
            "networkscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
        )


class NetworkScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_scans.html"

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

            item = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item.delete()
            item_results = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item_results.delete()
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

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
            delete_vuln = NetworkScanResultsDb.objects.filter(
                vuln_id=vuln_id, organization=request.user.organization
            )
            delete_vuln.delete()
        all_vuln = (
            NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            .exclude(severity="Information")
            .exclude(severity="Log")
        )

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        # total_info = len(all_vuln.filter(severity="Information"))

        NetworkScanDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            organization=request.user.organization
            # info_vul=total_info,
        )
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))
