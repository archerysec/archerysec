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

import json
import time
import uuid

from django.core import signing
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from PyBurprestapi import burpscanner
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

import PyArachniapi
from archerysettings.models import (ArachniSettingsDb, BurpSettingDb, EmailDb,
                                    OpenvasSettingDb, SettingsDb,
                                    ZapSettingsDb)
from jiraticketing.models import jirasetting
from scanners.scanner_plugin.network_scanner.openvas_plugin import \
    OpenVAS_Plugin
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from user_management import permissions
from utility.email_notify import email_sch_notify


class EmailSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/email_setting_form.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_email = EmailDb.objects.filter(organization=request.user.organization)
        return render(
            request, "setting/email_setting_form.html", {"all_email": all_email}
        )

    def post(self, request):
        all_email = EmailDb.objects.filter(organization=request.user.organization)

        email_setting_data = SettingsDb.objects.filter(setting_scanner="Email", organization=request.user.organization)

        subject = request.POST.get("email_subject")
        from_message = request.POST.get("email_message")
        email_to = request.POST.get("to_email")

        all_email.delete()
        email_setting_data.delete()

        setting_id = uuid.uuid4()

        save_email = EmailDb(
            subject=subject,
            message=from_message,
            recipient_list=email_to,
            setting_id=setting_id,
            organization=request.user.organization
        )
        save_email.save()

        subject_test = "test"
        message = "test"

        email = email_sch_notify(subject=subject_test, message=message)

        if email is False:
            setting_status = False
        else:
            setting_status = True

        save_setting_info = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Email",
            setting_status=setting_status,
            organization=request.user.organization
        )
        save_setting_info.save()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class DeleteSettings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        setting_id = request.POST.get("setting_id")

        delete_dat = SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization)
        delete_dat.delete()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class Settings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/settings_page.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_notify = Notification.objects.unread()

        all_settings_data = SettingsDb.objects.filter(organization=request.user.organization)

        return render(
            request,
            "setting/settings_page.html",
            {"all_settings_data": all_settings_data, "all_notify": all_notify},
        )

    def post(self, request):
        all_notify = Notification.objects.unread()

        jira_url = None
        j_username = None
        password = None
        # Loading settings

        all_settings_data = SettingsDb.objects.filter(organization=request.user.organization)

        # Loading ZAP Settings
        # zap_api_key = ""
        # zap_hosts = ""
        # zap_ports = ""
        # zap_enable = False

        all_zap = ZapSettingsDb.objects.filter(organization=request.user.organization)
        # for zap in all_zap:
        #   zap_api_key = zap.zap_api
        #   zap_hosts = zap.zap_url
        #   zap_ports = zap.zap_port
        #   zap_enable = zap.enabled

        # lod_apikey = zap_api_key
        # zap_host = zap_hosts
        # zap_port = zap_ports

        # Loading Arachni Settings
        arachni_hosts = ""
        arachni_ports = ""
        arachni_user = ""
        arachni_pass = ""

        all_arachni = ArachniSettingsDb.objects.filter(organization=request.user.organization)
        for arachni in all_arachni:
            arachni_hosts = arachni.arachni_url
            arachni_ports = arachni.arachni_port
            arachni_user = arachni.arachni_user
            arachni_pass = arachni.arachni_pass

        burp_host = ""
        burp_port = ""
        burp_api_key = ""
        all_burp_setting = BurpSettingDb.objects.filter(organization=request.user.organization)
        for data in all_burp_setting:
            burp_host = data.burp_url
            burp_port = data.burp_port
            burp_api_key = data.burp_api_key

        jira_setting = jirasetting.objects.filter(organization=request.user.organization)

        for jira in jira_setting:
            jira_url = jira.jira_server
            j_username = jira.jira_username
            password = jira.jira_password
        jira_server = jira_url
        if j_username is None:
            jira_username = None
        else:
            jira_username = signing.loads(j_username)

        if password is None:
            jira_password = None
        else:
            jira_password = signing.loads(password)

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"

        setting_of = request.POST.get("setting_of")
        setting_id = request.POST.get("setting_id")
        if setting_of == "zap":
            all_zap = ZapSettingsDb.objects.filter(organization=request.user.organization)
            for zap in all_zap:
                zap_enabled = zap.enabled

            if zap_enabled is False:
                zap_info = "Disabled"
                try:
                    random_port = zap_plugin.zap_local()
                except Exception:
                    return render(
                        request, "setting/settings_page.html", {"zap_info": zap_info}
                    )

                for i in range(0, 100):
                    while True:
                        try:
                            # Connection Test
                            zap_connect = zap_plugin.zap_connect(random_port)
                            zap_connect.spider.scan(url=target_url)
                        except Exception:
                            print("ZAP Connection Not Found, re-try after 5 sec")
                            time.sleep(5)
                            continue
                        break
            else:
                try:
                    zap_connect = zap_plugin.zap_connect(random_port)
                    zap_connect.spider.scan(url=target_url)
                    zap_info = True
                    SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                        setting_status=zap_info
                    )
                except Exception:
                    zap_info = False
                    SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                        setting_status=zap_info
                    )
        if setting_of == "burp":
            host = "http://" + burp_host + ":" + burp_port + "/"

            try:
                bi = burpscanner.BurpApi(host, burp_api_key)
            except Exception:
                burp_info = False
                return burp_info

            issue_list = bi.issue_definitions()
            if issue_list.data is None:
                burp_info = False
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=burp_info
                )
            else:
                burp_info = True
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=burp_info
                )

        if setting_of == "openvas":
            sel_profile = ""
            scan_ip = ""
            project_id = ""

            openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile)
            try:
                openvas.connect()
                openvas_info = True
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=openvas_info
                )
            except Exception:
                openvas_info = False
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=openvas_info
                )

        if setting_of == "arachni":
            global scan_run_id, scan_status
            arachni_hosts = None
            arachni_ports = None
            arachni_user = None
            arachni_pass = None
            all_arachni = ArachniSettingsDb.objects.filter(organization=request.user.organization)
            for arachni in all_arachni:
                arachni_hosts = arachni.arachni_url
                arachni_ports = arachni.arachni_port
                arachni_user = arachni.arachni_user
                arachni_pass = arachni.arachni_pass

            arachni = PyArachniapi.arachniAPI(
                arachni_hosts, arachni_ports, arachni_user, arachni_pass
            )

            check = []
            data = {"url": "https://archerysec.com", "checks": check, "audit": {}}
            d = json.dumps(data)

            scan_launch = arachni.scan_launch(d)
            time.sleep(3)

            try:
                scan_data = scan_launch.data

                for key, value in scan_data.items():
                    if key == "id":
                        scan_run_id = value
                arachni_info = True
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=arachni_info
                )
            except Exception:
                arachni_info = False
                SettingsDb.objects.filter(setting_id=setting_id, organization=request.user.organization).update(
                    setting_status=arachni_info
                )

        if setting_of == "jira":
            global jira_projects, jira_ser
            jira_setting = jirasetting.objects.filter(organization=request.user.organization)

            for jira in jira_setting:
                jira_url = jira.jira_server
                username = jira.jira_username
                password = jira.jira_password

                if jira_url is None:
                    print("No jira url found")

            try:

                jira_server = jira_url
                jira_username = signing.loads(username)
                jira_password = signing.loads(password)
            except Exception:
                jira_info = False

            options = {"server": jira_server}
            try:

                if jira_username is not None and jira_username != "" :
                    jira_ser = JIRA(
                        options, basic_auth=(jira_username, jira_password), timeout=5
                    )
                else :
                    jira_ser = JIRA(options, token_auth=jira_password, timeout=5)

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

        return render(
            request,
            "setting/settings_page.html",
            {"all_settings_data": all_settings_data, "all_notify": all_notify},
        )
