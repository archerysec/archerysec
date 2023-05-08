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

import json
import os
import threading
import time
import uuid
from datetime import datetime

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.signals import notify
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView
from selenium import webdriver
from notifications.signals import notify
from rest_framework.response import Response

from archerysettings.models import EmailDb, SettingsDb, ZapSettingsDb
from projects.models import ProjectDb
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from user_management import permissions
from webscanners.models import WebScansDb, cookie_db, excluded_db
from webscanners.zapscanner.serializers import ZapScansSerializer, ZapSettingsSerializer

scans_status = None
to_mail = ""
scan_id = None
scan_name = None


def email_notify(user, subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb='Email Settings Not Configured')


def email_sch_notify(subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        print(e)


def launch_zap_scan(target_url, project_id, rescan_id, rescan, scan_id, user, request):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    zap_enabled = False
    random_port = "8091"

    all_zap = ZapSettingsDb.objects.filter(organization=request.user.organization)
    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        print("started local instence")
        random_port = zap_plugin.zap_local()

        for i in range(0, 100):
            while True:
                try:
                    # Connection Test
                    zap_connect = zap_plugin.zap_connect(random_port)
                    zap_connect.spider.scan(url=target_url)
                except Exception as e:
                    print("ZAP Connection Not Found, re-try after 5 sec")
                    time.sleep(5)
                    continue
                break

    zap_plugin.zap_spider_thread(count=20, random_port=random_port)
    zap_plugin.zap_spider_setOptionMaxDepth(count=5, random_port=random_port)

    zap_plugin.zap_scan_thread(count=30, random_port=random_port)
    zap_plugin.zap_scan_setOptionHostPerScan(count=3, random_port=random_port)

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
        request=request,
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
            organization=request.user.organization
        )

        save_all_scan.save()
        notify.send(user, recipient=user, verb="ZAP Scan URL %s Added" % target_url)
    except Exception as e:
        print(e)

    notify.send(user, recipient=user, verb="ZAP Scan Started")
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    notify.send(user, recipient=user, verb="ZAP Scan Spider Completed")
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    save_all_vuln = zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
        request=request
    )
    all_zap_scan = WebScansDb.objects.filter(scanner="zap", organization=request.user.organization)

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    if zap_enabled is False:
        zap.zap_shutdown()

    notify.send(user, recipient=user, verb="ZAP Scan URL %s Completed" % target_url)

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )
    email_sch_notify(subject=subject, message=message)


def launch_schudle_zap_scan(target_url, project_id, rescan_id, rescan, scan_id, request):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    random_port = "8090"

    # Connection Test
    zap_connect = zap_plugin.zap_connect(random_port)

    try:
        zap_connect.spider.scan(url=target_url)

    except Exception:
        subject = "ZAP Connection Not Found"
        message = "ZAP Scanner failed due to setting not found "

        email_sch_notify(subject=subject, message=message)
        print("ZAP Connection Not Found")
        return HttpResponseRedirect(reverse("webscanners:index"))

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url, project_id, rescan_id, rescan, random_port=random_port, request=request
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
            organization=request.user.organization
        )

        save_all_scan.save()
    except Exception as e:
        print(e)
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
        request=request
    )
    all_zap_scan = WebScansDb.objects.filter(scanner="zap", organization=request.user.organization)

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


class ZapScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scans_status = ""
        scan_id = ""
        project_uu_id = None
        target_url = None
        user = request.user

        if request.path[: 4] == '/api':
            _url = None
            _project_id = None

            serializer = ZapScansSerializer(data=request.data)
            if serializer.is_valid():
                target_url = request.data.get(
                    "url",
                )

                project_uu_id = request.data.get(
                    "project_id",
                )
        else:
            target_url = request.POST.get("url")
            project_uu_id = request.POST.get("project_id")
        project_id = (
            ProjectDb.objects.filter(uu_id=project_uu_id, organization=request.user.organization).values("id").get()["id"]
        )
        rescan_id = None
        rescan = "No"
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, user, request),
            )
            thread.daemon = True
            thread.start()
            time.sleep(10)
        if scans_status == "100":
            scans_status = "0"
        else:
            if request.path[: 4] == '/api':
                return Response({"scan_id": scan_id})
            return HttpResponse(status=200)

        if request.path[: 4] == '/api':
            return Response({"scan_id": scan_id})
        else:
            return render(request, "webscanners/zapscanner/zap_scan_list.html")


class ZapSetting(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        zap_api_key = ""
        zap_hosts = None
        zap_ports = None
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_api_key = zap.zap_api
            zap_hosts = zap.zap_url
            zap_ports = zap.zap_port
            zap_enabled = zap.enabled

        if zap_enabled:
            zap_enabled = "True"
        else:
            zap_enabled = "False"

        if request.path[: 4] == '/api':
            return Response({"zap_api_key": zap_api_key,
                             "zap_hosts": zap_hosts,
                             "zap_ports": zap_ports,
                             "zap_enabled": zap_enabled,
                             })
        else:
            return render(
                request,
                "webscanners/zapscanner/zap_settings_form.html",
                {
                    "zap_apikey": zap_api_key,
                    "zap_host": zap_hosts,
                    "zap_port": zap_ports,
                    "zap_enabled": zap_enabled,
                },
            )


class ZapSettingUpdate(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(request, "webscanners/zapscanner/zap_settings_form.html")

    def post(self, request):
        zaphost = 'NA'
        port = 'NA'
        apikey = 'NA'

        all_zap = ZapSettingsDb.objects.filter()
        all_zap.delete()

        all_zap_data = SettingsDb.objects.filter(setting_scanner="Zap")
        all_zap_data.delete()

        if request.POST.get("zap_enabled") == "on":
            zap_enabled = True
        else:
            zap_enabled = False

        if request.path[: 4] == '/api':
            serializer = ZapSettingsSerializer(data=request.data)
            if serializer.is_valid():
                apikey = request.data.get(
                    "zap_api_key",
                )
                zaphost = request.data.get(
                    "zap_host",
                )
                port = request.data.get(
                    "zap_port",
                )
                zap_enabled = request.data.get(
                    "zap_enabled",
                )
        else:
            apikey = request.POST.get(
                "apikey",
            )
            zaphost = request.POST.get(
                "zappath",
            )
            port = request.POST.get(
                "port",
            )

        setting_id = uuid.uuid4()

        save_zap_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Zap",
        )
        save_zap_data.save()

        save_data = ZapSettingsDb(
            setting_id=setting_id,
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey,
            enabled=zap_enabled,
        )
        save_data.save()

        if request.path[: 4] == '/api':
            if zap_enabled is False:
                return Response ({"message": "OWASP ZAP scanner updated!!!"})

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"
        zap_info = ""

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            if request.path[: 4] == '/api':
                return Response({"message": "OWASP ZAP Scanner Disabled"})
            zap_info = "Disabled"
            try:
                random_port = zap_plugin.zap_local()
            except:
                return render(
                    request, "setting/settings_page.html", {"zap_info": zap_info}
                )

            for i in range(0, 100):
                while True:
                    try:
                        # Connection Test
                        zap_connect = zap_plugin.zap_connect(random_port)
                        zap_connect.spider.scan(url=target_url)
                    except Exception as e:
                        print("ZAP Connection Not Found, re-try after 5 sec")
                        time.sleep(5)
                        continue
                    break
        else:
            try:
                zap_connect = zap_plugin.zap_connect(
                    random_port,
                )
                zap_connect.spider.scan(url=target_url)
                zap_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )
                if request.path[: 4] == '/api':
                    return Response({"message": "OWASP ZAP scanner updated!!!"})
            except:
                zap_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )
                if request.path[: 4] == '/api':
                    return Response({"message": "Not updated, Something Wrong !!!"})

        return HttpResponseRedirect(reverse("archerysettings:settings"))
