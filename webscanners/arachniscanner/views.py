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

import defusedxml.ElementTree as ET
from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from notifications.signals import notify

import PyArachniapi
from archerysettings.models import arachni_settings_db
from jiraticketing.models import jirasetting
from scanners.scanner_parser.web_scanner import arachni_xml_parser
from webscanners.models import (WebScanResultsDb, WebScansDb)
from webscanners.resources import ArachniResource

scan_run_id = ""
scan_status = ""


def launch_arachni_scan(target, project_id, rescan_id, rescan, scan_id, user):
    global scan_run_id, scan_status
    arachni_hosts = None
    arachni_ports = None
    username = user.username
    all_arachni = arachni_settings_db.objects.filter(username=username)
    for arachni in all_arachni:
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port

    arachni = PyArachniapi.arachniAPI(arachni_hosts, arachni_ports)
    check = [
        "xss_event",
        "xss",
        "xss_script_context",
        "xss_tag",
        "xss_path",
        "xss_dom_script_context",
        "xss_dom",
        "sql_injection",
        "sql_injection_differential",
        "sql_injection_timing",
        "no_sql_injection",
        "no_sql_injection_differential",
        "code_injection",
        "code_injection_timing",
        "ldap_injection",
        "path_traversal",
        "file_inclusion",
        "response_splitting",
        "os_cmd_injection",
        "os_cmd_injection_timing",
        "rfi",
        "unvalidated_redirect",
        "unvalidated_redirect_dom",
        "xpath_injection",
        "xxe",
        "source_code_disclosure",
        "allowed_methods",
        "backup_files",
        "backup_directories",
        "common_admin_interfaces",
        "common_directories",
        "common_files",
        "http_put",
        "webdav",
        "xst",
        "credit_card",
        "cvs_svn_users",
        "private_ip",
        "backdoors",
        "htaccess_limit",
        "interesting_responses",
        "html_objects",
        "emails",
        "ssn",
        "directory_listing",
        "mixed_resource",
        "insecure_cookies",
        "http_only_cookies",
        "password_autocomplete",
        "origin_spoof_access_restriction_bypass",
        "form_upload",
        "localstart_asp",
        "cookie_set_for_parent_domain",
        "hsts",
        "x_frame_options",
        "insecure_cors_policy",
        "insecure_cross_domain_policy_access",
        "insecure_cross_domain_policy_headers",
        "insecure_client_access_policy",
        "csrf",
        "common_files",
        "directory_listing",
    ]

    data = {"url": target, "checks": check, "audit": {}}
    d = json.dumps(data)

    scan_launch = arachni.scan_launch(d)
    time.sleep(3)

    try:
        scan_data = scan_launch.data

        for key, value in scan_data.items():
            if key == "id":
                scan_run_id = value
        notify.send(
            user, recipient=user, verb="Arachni Scan Started on URL %s" % target
        )
    except Exception:
        notify.send(user, recipient=user, verb="Arachni Connection Not found")
        print("Arachni Connection Not found")
        return

    date_time = datetime.now()

    try:
        save_all_scan = WebScansDb(
            username=username,
            project_id=project_id,
            scan_url=target,
            scan_id=scan_id,
            date_time=date_time,
        )

        save_all_scan.save()

    except Exception as e:
        print(e)

    scan_data = scan_launch.data

    for key, value in scan_data.items():
        if key == "id":
            scan_run_id = value

    scan_sum = arachni.scan_summary(id=scan_run_id).data
    for key, value in scan_sum.items():
        if key == "status":
            scan_status = value
    while scan_status != "done":
        status = "0"
        if (
            scan_sum["statistics"]["browser_cluster"]["queued_job_count"]
            and scan_sum["statistics"]["browser_cluster"]["total_job_time"]
        ):
            status = (
                100
                - scan_sum["statistics"]["browser_cluster"]["queued_job_count"]
                * 100
                / scan_sum["statistics"]["browser_cluster"]["total_job_time"]
            )
        WebScansDb.objects.filter(username=username, scan_id=scan_id, scanner='Arachni').update(
            scan_status=int(status)
        )
        scan_sum = arachni.scan_summary(id=scan_run_id).data
        for key, value in scan_sum.items():
            if key == "status":
                scan_status = value
        time.sleep(3)
    if scan_status == "done":
        xml_report = arachni.scan_xml_report(id=scan_run_id).data
        root_xml = ET.fromstring(xml_report)
        arachni_xml_parser.xml_parser(
            username=username,
            project_id=project_id,
            scan_id=scan_id,
            root=root_xml,
            target_url=target,
        )
        WebScansDb.objects.filter(username=username, scan_id=scan_id, scanner='Arachni').update(
            scan_status="100"
        )
        print("Data uploaded !!!!")

    notify.send(user, recipient=user, verb="Arachni Scan Completed on URL %s" % target)


def arachni_scan(request):
    """
    The function trigger Arachni scan.
    :param request:
    :return:
    """
    user = request.user
    if request.method == "POST":
        target_url = request.POST.get("scan_url")
        project_id = request.POST.get("project_id")
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
                target=launch_arachni_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, user),
            )
            thread.daemon = True
            thread.start()

    return render(request, "webscanners/arachniscanner/arachni_scan_list.html")


def arachni_settings(request):
    """
    The function calling arachni Scanner setting page.
    :param request:
    :return:
    """
    username = request.user.username
    arachni_hosts = None
    arachni_ports = None

    all_arachni = arachni_settings_db.objects.filter(username=username)
    for arachni in all_arachni:
        # global arachni_api_key, arachni_hosts, arachni_ports
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port

    return render(
        request,
        "webscanners/arachniscanner/arachni_settings_form.html",
        {
            "arachni_host": arachni_hosts,
            "arachni_port": arachni_ports,
        },
    )


def arachni_setting_update(request):
    """
    The function Update the arachni settings.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == "POST":
        arachnihost = request.POST.get(
            "arachnihost",
        )
        port = request.POST.get(
            "arachniport",
        )
        save_data = arachni_settings_db(
            username=username,
            arachni_url=arachnihost,
            arachni_port=port,
        )
        save_data.save()

        return HttpResponseRedirect(reverse("webscanners:setting"))

    return render(request, "webscanners/arachniscanner/arachni_settings_form.html")


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

        zap_resource = ArachniResource()
        queryset = WebScanResultsDb.objects.filter(
            username=username, scan_id__in=value_split, scanner='Arachni'
        )
        dataset = zap_resource.export(queryset)
        if report_type == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = (
                'attachment; filename="%s.csv"' % "arachni_results"
            )
            return response
        if report_type == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = (
                'attachment; filename="%s.json"' % "arachni_results"
            )
            return response
        if report_type == "yaml":
            response = HttpResponse(dataset.yaml, content_type="application/x-yaml")
            response["Content-Disposition"] = (
                'attachment; filename="%s.yaml"' % "arachni_results"
            )
            return response
