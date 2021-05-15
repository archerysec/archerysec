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
import threading
import time
import uuid
from datetime import datetime

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from notifications.models import Notification
from notifications.signals import notify
from PyBurprestapi import burpscanner

from archerysettings.models import burp_setting_db
from jiraticketing.models import jirasetting
from scanners.scanner_plugin.web_scanner import burp_plugin
from webscanners.models import (WebScansDb,
                                WebScanResultsDb)
from webscanners.resources import BurpResource

burp_url = None
burp_port = None
burp_api_key = None
remediation = None
issue_type_id = None
description = None
name = None
references = None
vulnerability_classifications = None


def burp_setting(request):
    """
    Load Burp Settings.
    :param request:
    :return:
    """
    username = request.user.username
    user = request.user

    all_burp_setting = burp_setting_db.objects.filter(username=username)

    for data in all_burp_setting:
        global burp_url, burp_port, burp_api_key, remediation, issue_type_id, description, name, references, vulnerability_classifications
        burp_url = data.burp_url
        burp_port = data.burp_port
        burp_api_key = data.burp_api_key

    if request.method == "POST":
        burphost = request.POST.get("burpath")
        burport = request.POST.get("burport")
        burpapikey = request.POST.get("burpapikey")
        save_burp_settings = burp_setting_db(
            username=username,
            burp_url=burphost,
            burp_port=burport,
            burp_api_key=burpapikey,
        )
        save_burp_settings.save()

        host = "http://" + burphost + ":" + burport + "/"

        bi = burpscanner.BurpApi(host, burpapikey)

        issue_list = bi.issue_definitions()

        json_issue_data = json.dumps(issue_list.data)
        issues = json.loads(json_issue_data)

        try:
            for issue_dat in issues:
                for key, values in issue_dat.items():
                    if key == "remediation":
                        remediation = values
                    if key == "issue_type_id":
                        issue_type_id = values
                    if key == "description":
                        description = values
                    if key == "name":
                        name = values
                    if key == "references":
                        references = values
                    if key == "vulnerability_classifications":
                        vulnerability_classifications = values

        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb="Burp Connection Not Found")

        return HttpResponseRedirect(reverse("webscanners:setting"))

    return render(
        request,
        "burpscanner/burp_setting_form.html",
        {"burp_url": burp_url, "burp_port": burp_port, "burp_api_key": burp_api_key},
    )


def burp_scan_launch(request):
    """
    Burp Scan Trigger.
    :param request:
    :return:
    """
    username = request.user.username
    user = request.user

    global vuln_id, burp_status
    if request.POST.get("url"):
        target_url = request.POST.get("url")
        project_id = request.POST.get("project_id")
        target__split = target_url.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print("Targets"), target
            scan_id = uuid.uuid4()
            try:
                do_scan = burp_plugin.burp_scans(project_id, target, scan_id, user)

                thread = threading.Thread(
                    target=do_scan.scan_launch,
                )
                thread.daemon = True
                thread.start()
                time.sleep(5)
            except Exception as e:
                print(e)

    return render(request, "burpscanner/burp_scan_list.html")


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == "POST":
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")

        zap_resource = BurpResource()
        queryset = WebScanResultsDb.objects.filter(
            username=username, scanner='Burp', scan_id__in=value_split
        )
        dataset = zap_resource.export(queryset)
        if report_type == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = (
                'attachment; filename="%s.csv"' % "burp_results"
            )
            return response
        if report_type == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = (
                'attachment; filename="%s.json"' % "burp_results"
            )
            return response
        if report_type == "yaml":
            response = HttpResponse(dataset.yaml, content_type="application/x-yaml")
            response["Content-Disposition"] = (
                'attachment; filename="%s.yaml"' % "burp_results"
            )
            return response
