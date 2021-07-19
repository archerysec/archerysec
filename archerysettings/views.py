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
import os
import threading
import time
import uuid
from datetime import datetime

import defusedxml.ElementTree as ET
from background_task import background
from background_task.models import Task
from django.contrib import auth, messages
from django.contrib.auth.models import User
from django.core import signing
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from jira import JIRA
from lxml import etree
from notifications.models import Notification
from PyBurprestapi import burpscanner
from selenium import webdriver
from stronghold.decorators import public

import PyArachniapi
from archerysettings import load_settings
from archerysettings.models import (ArachniSettingsDb,
                                    EmailDb, NmapVulnersSettingDb,
                                    ZapSettingsDb, SettingsDb)
from jiraticketing.models import jirasetting
from projects.models import ProjectDb
from scanners.scanner_parser.staticscanner_parser import (
    checkmarx_xml_report_parser, dependencycheck_report_parser,
    findbugs_report_parser)
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from scanners.scanner_parser.web_scanner import (acunetix_xml_parser,
                                                 arachni_xml_parser,
                                                 burp_xml_parser,
                                                 netsparker_xml_parser,
                                                 webinspect_xml_parser,
                                                 zap_xml_parser)
from scanners.scanner_plugin.network_scanner.openvas_plugin import \
    OpenVAS_Plugin
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from staticscanners.models import (StaticScansDb)
from tools.models import NiktoResultDb
from webscanners.models import (WebScansDb, cookie_db,
                                excluded_db,
                                task_schedule_db)
from webscanners.zapscanner.views import launch_schudle_zap_scan
import uuid

setting_file = os.getcwd() + "/" + "apidata.json"

# All global variable
spider_status = "0"
scans_status = "0"
spider_alert = ""
target_url = ""
driver = ""
new_uri = ""
cookies = ""
excluded_url = ""
vul_col = ""
note = ""
rtt = ""
tags = ""
timestamp = ""
responseHeader = ""
requestBody = ""
responseBody = ""
requestHeader = ""
cookieParams = ""
res_type = ""
res_id = ""
alert = ""
project_id = None
# target_url = None
scan_ip = None
# burp_status = 0
serialNumber = ""
types = ""
name = ""
host = ""
path = ""
location = ""
severity = ""
confidence = ""
issueBackground = ""
remediationBackground = ""
references = ""
vulnerabilityClassifications = ""
issueDetail = ""
requestresponse = ""
# vuln_id = ""
methods = ""
dec_res = ""
dec_req = ""
decd_req = ""
scanner = ""
all_scan_url = ""
all_url_vuln = ""
zap_apikey = None
zap_host = None
zap_port = None


def setting(request):
    """
    The function calling setting page.
    :param request:
    :return:
    """
    all_notify = Notification.objects.unread()

    jira_url = None
    j_username = None
    password = None
    # Loading settings


    settings = load_settings.ArcherySettings(setting_file)

    all_settings_data = SettingsDb.objects.filter()

    lod_ov_user = settings.openvas_username()
    lod_ov_pass = settings.openvas_pass()
    lod_ov_host = settings.openvas_host()
    lod_ov_port = settings.openvas_port()
    lod_ov_enabled = settings.openvas_enabled()

    # Loading ZAP Settings
    zap_api_key = ""
    zap_hosts = ""
    zap_ports = ""
    zap_enable = False

    all_zap = ZapSettingsDb.objects.filter()
    for zap in all_zap:
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port
        zap_enable = zap.enabled

    lod_apikey = zap_api_key
    zap_host = zap_hosts
    zap_port = zap_ports

    # Loading Arachni Settings
    arachni_hosts = ''
    arachni_ports = ''
    arachni_user = ''
    arachni_pass = ''

    all_arachni = ArachniSettingsDb.objects.filter()
    for arachni in all_arachni:
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port
        arachni_user = arachni.arachni_user
        arachni_pass = arachni.arachni_pass

    arachni_hosts = arachni_hosts
    arachni_ports = arachni_ports
    arachni_user = arachni_user
    arachni_pass = arachni_pass

    # Loading NMAP Vulners Settings
    nv_enabled = False
    nv_online = False
    nv_version = False
    nv_timing = 0

    all_nv = NmapVulnersSettingDb.objects.filter()
    for nv in all_nv:
        nv_enabled = bool(nv.enabled)
        nv_online = bool(nv.online)
        nv_version = bool(nv.version)
        nv_timing = int(nv.timing)

    # Loading Burp Settings

    burp_host = settings.burp_host()
    burp_port = settings.burp_port()
    burp_api_key = settings.burp_api_key()

    # Loading Email Settings

    all_email = EmailDb.objects.filter()

    # Load JIRA Setting
    jira_setting = jirasetting.objects.filter()

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
    zap_info = ""
    burp_info = ""
    openvas_info = ""
    arachni_info = ""
    jira_info = ""

    if request.method == "POST":
        setting_of = request.POST.get("setting_of")
        setting_id = request.POST.get("setting_id")
        if setting_of == "zap":
            all_zap = ZapSettingsDb.objects.filter()
            for zap in all_zap:
                zap_enabled = zap.enabled

            if zap_enabled is False:
                zap_info = "Disabled"
                try:
                    random_port = zap_plugin.zap_local()
                except:
                    return render(request, "setting/settings_page.html", {"zap_info": zap_info})

                for i in range(0, 100):
                    while True:
                        try:
                            # Connection Test
                            zap_connect = zap_plugin.zap_connect(
                                random_port, 
                            )
                            zap_connect.spider.scan(url=target_url)
                        except Exception as e:
                            print("ZAP Connection Not Found, re-try after 5 sec")
                            time.sleep(5)
                            continue
                        break
            else:
                try:
                    zap_connect = zap_plugin.zap_connect(random_port, )
                    zap_connect.spider.scan(url=target_url)
                    zap_info = True
                    SettingsDb.objects.filter(setting_id=setting_id).update(
                        setting_status=zap_info
                    )
                except:
                    zap_info = False
                    SettingsDb.objects.filter(setting_id=setting_id).update(
                        setting_status=zap_info
                    )
        if setting_of == "burp":
            host = "http://" + burp_host + ":" + burp_port + "/"

            try:
                bi = burpscanner.BurpApi(host, burp_api_key)
            except:
                burp_info = False
                return burp_info

            issue_list = bi.issue_definitions()
            if issue_list.data is None:
                burp_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=burp_info
                )
            else:
                burp_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=burp_info
                )

        if setting_of == "openvas":
            sel_profile = ""

            openvas = OpenVAS_Plugin(
                scan_ip, project_id, sel_profile, 
            )
            try:
                openvas.connect()
                openvas_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=openvas_info
                )
            except:
                openvas_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=openvas_info
                )

        if setting_of == "arachni":
            global scan_run_id, scan_status
            arachni_hosts = None
            arachni_ports = None
            arachni_user = None
            arachni_pass = None
            all_arachni = ArachniSettingsDb.objects.filter()
            for arachni in all_arachni:
                arachni_hosts = arachni.arachni_url
                arachni_ports = arachni.arachni_port
                arachni_user = arachni.arachni_user
                arachni_pass = arachni.arachni_pass

            arachni = PyArachniapi.arachniAPI(arachni_hosts, arachni_ports, arachni_user, arachni_pass)

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
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=arachni_info
                )
            except Exception:
                arachni_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=arachni_info
                )

        if setting_of == "jira":
            global jira_projects, jira_ser
            jira_setting = jirasetting.objects.filter()

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
            except:
                jira_info = False

            options = {"server": jira_server}
            try:

                jira_ser = JIRA(
                    options, basic_auth=(jira_username, jira_password), timeout=5
                )
                jira_projects = jira_ser.projects()
                print(len(jira_projects))
                jira_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=jira_info
                )
            except Exception as e:
                print(e)
                jira_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=jira_info
                )

    return render(request, 'setting/settings_page.html',
                  {'apikey': lod_apikey,
                   'zapath': zap_host,
                   'zap_port': zap_port,
                   'zap_enable': zap_enable,
                   'arachni_hosts': arachni_hosts,
                   'arachni_ports': arachni_ports,
                   'arachni_user': arachni_user,
                   'arachni_pass': arachni_pass,
                   'lod_ov_user': lod_ov_user,
                   'lod_ov_pass': lod_ov_pass,
                   'lod_ov_host': lod_ov_host,
                   'lod_ov_enabled': lod_ov_enabled,
                   'lod_ov_port': lod_ov_port,
                   'burp_path': burp_host,
                   'burp_port': burp_port,
                   'burp_api_key': burp_api_key,
                   'all_email': all_email,
                   'jira_server': jira_server,
                   'jira_username': jira_username,
                   'jira_password': jira_password,
                   'nv_enabled': nv_enabled,
                   'nv_version': nv_version,
                   'nv_online': nv_online,
                   'nv_timing': nv_timing,
                   'message': all_notify,
                   'zap_info': zap_info,
                   'burp_info': burp_info,
                   'openvas_info': openvas_info,
                   'arachni_info': arachni_info,
                   'jira_info': jira_info,
                   'all_settings_data': all_settings_data
                   })


def email_setting(request):
    """
    The function calling and updating Email Settings.
    :param request:
    :return:
    """
    # Load Email Setting function
    all_email = EmailDb.objects.filter()

    email_setting_data = SettingsDb.objects.filter(setting_scanner='Email')

    if request.method == "POST":
        subject = request.POST.get("email_subject")
        from_message = request.POST.get("email_message")
        email_to = request.POST.get("to_email")

        all_email.delete()
        email_setting_data.delete()

        setting_id = uuid.uuid4()

        save_setting_info = SettingsDb(
            setting_id=setting_id,
            
            setting_scanner='Email',
            setting_status=True,
        )
        save_setting_info.save()

        save_email = EmailDb(
            
            subject=subject,
            message=from_message,
            recipient_list=email_to,
            setting_id=setting_id,
        )
        save_email.save()
        return HttpResponseRedirect(reverse("archerysettings:settings"))

    return render(request, "setting/email_setting_form.html", {"all_email": all_email})


def del_setting(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        setting_id = request.POST.get("setting_id")

        delete_dat = SettingsDb.objects.filter(setting_id=setting_id)
        delete_dat.delete()
        return HttpResponseRedirect(reverse("archerysettings:settings"))

    return render(request, "setting/settings_page.html")
