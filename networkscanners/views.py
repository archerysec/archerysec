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

import defusedxml.ElementTree as ET
from background_task import background
from background_task.models import Task
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.utils import timezone
from notifications.models import Notification
from notifications.signals import notify

from archerysettings import load_settings, save_settings
from archerysettings.models import email_db, settings_db
from jiraticketing.models import jirasetting
from networkscanners.models import (task_schedule_db)
from networkscanners.models import (NetworkScanResultsDb, NetworkScanDb)
from projects.models import project_db
from scanners.scanner_parser.network_scanner import (Nessus_Parser,
                                                     OpenVas_Parser,
                                                     nmap_parser)
from scanners.scanner_plugin.network_scanner.openvas_plugin import (
    OpenVAS_Plugin, vuln_an_id)

api_data = os.getcwd() + "/" + "apidata.json"

status = ""
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
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        pass


def list_scans(request):
    username = request.user.username
    scan_list = NetworkScanDb.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(request, "networkscanners/scans/list_scans.html", {"all_scans": scan_list, "message": all_notify})


def list_vuln_info(request):
    scan_id = None
    name = None
    scanner = None
    ip = ''

    username = request.user.username
    jira_url = None

    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        scanner = request.GET['scanner']
        ip = request.GET['ip']
    if request.method == "POST":
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")
        ip = request.POST.get("ip")
        NetworkScanResultsDb.objects.filter(
            username=username, vuln_id=vuln_id, scan_id=scan_id, scanner=scanner
        ).update(false_positive=false_positive, vuln_status=status)

        if false_positive == "Yes":
            vuln_info = NetworkScanResultsDb.objects.filter(
                username=username, scan_id=scan_id, vuln_id=vuln_id, scanner=scanner
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
                    username=username, vuln_id=vuln_id, scan_id=scan_id, scanner=scanner
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                )

        all_vuln = NetworkScanResultsDb.objects.filter(
            username=username, scan_id=scan_id, false_positive="No", vuln_status="Open", scanner=scanner
        )

        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info

        NetworkScanDb.objects.filter(username=username, scan_id=scan_id, scanner=scanner).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup
        )
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln_info") + "?scan_id=%s&ip=%s&scanner=%s" % (scan_id, ip, scanner)
        )

    vuln_data = NetworkScanResultsDb.objects.filter(
        username=username,
        scan_id=scan_id,
        scanner=scanner,
        ip=ip
    )

    return render(request, "networkscanners/scans/list_vuln_info.html", {"vuln_data": vuln_data, "jira_url": jira_url})


def scan_details(request):
    username = request.user.username
    if request.method == "GET":
        vuln_id = request.GET["vuln_id"]
        scanner = request.GET["scanner"]
    else:
        vuln_id = ""
        scanner = ""
    vul_dat = NetworkScanResultsDb.objects.filter(
        username=username, vuln_id=vuln_id, scanner=scanner
    ).order_by("vuln_id")

    return render(request, "networkscanners/scans/vuln_details.html", {"vul_dat": vul_dat})


def scan_delete(request):
    username = request.user.username
    if request.method == "POST":
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = NetworkScanDb.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = NetworkScanResultsDb.objects.filter(
                username=username, scan_id=scan_id
            )
            item_results.delete()
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


def vuln_delete(request):
    username = request.user.username
    if request.method == "POST":
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = NetworkScanResultsDb.objects.filter(
                username=username, scanner=scanner, vuln_id=vuln_id
            )
            delete_vuln.delete()
        all_vuln = NetworkScanResultsDb.objects.filter(
            username=username, scanner=scanner, scan_id=scan_id
        )

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Information"))

        NetworkScanDb.objects.filter(username=username, scan_id=scan_id, scanner=scanner).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
        )
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln") + "?scan_id=%s&scanner=%s" % (scan_id, scanner)
        )


def openvas_scanner(scan_ip, project_id, sel_profile, username):
    """
    The function is launch the OpenVAS scans.
    :param scan_ip:
    :param project_id:
    :param sel_profile:
    :return:
    """
    user = User.objects.get(username=username)
    username = user.username
    openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile, username=username)
    try:
        scanner = openvas.connect()
    except Exception as e:

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
        username=username,
        scanner='Openvas'
    )
    save_all.save()
    openvas.scan_status(scanner=scanner, scan_id=scan_id)
    time.sleep(5)
    vuln_an_id(scan_id=scan_id, project_id=project_id, username=username)

    notify.send(user, recipient=user, verb="OpenVAS Scan Completed")

    all_openvas = NetworkScanDb.objects.filter(username=username)
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


def launch_scan(request):
    username = request.user.username
    """
    Function Trigger Network scans.
    :param request:
    :return:
    """
    all_ip = NetworkScanDb.objects.filter(username=username, scanner='Openvas')
    user = request.user

    if request.method == "POST":
        all_ip = NetworkScanDb.objects.filter(username=username)
        scan_ip = request.POST.get("ip")
        project_id = request.POST.get("project_id")
        sel_profile = request.POST.get("scan_profile")
        ip = scan_ip.replace(" ", "")
        target_split = ip.split(",")
        split_length = target_split.__len__()

        for i in range(0, split_length):
            target = target_split.__getitem__(i)

            thread = threading.Thread(
                target=openvas_scanner, args=(target, project_id, sel_profile, user)
            )
            thread.daemon = True
            thread.start()

    return render("networkscanners/openvas_vuln_list.html", {"all_ip": all_ip})


def ip_scan(request):
    username = request.user.username
    """
    List all network scan IP's.
    :param request:
    :return:
    """
    all_scans = NetworkScanDb.objects.filter(username=username)
    all_proj = project_db.objects.filter(username=username)

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


def openvas_details(request):
    username = request.user.username
    """
    OpenVAS tool settings.
    :param request:
    :return:
    """
    setting_id = uuid.uuid4()
    save_openvas_setting = save_settings.SaveSettings(api_data, username=username)
    if request.method == "POST":
        if request.POST.get("openvas_enabled") == "on":
            openvas_enabled = True
        else:
            openvas_enabled = False
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

        save_settings_data = settings_db(
            setting_id=setting_id,
            username=username,
            setting_scanner='Openvas'
        )
        save_settings_data.save()

        sel_profile = ""

        openvas = OpenVAS_Plugin(
            openvas_host, setting_id, sel_profile, username=username
        )
        try:
            openvas.connect()
            openvas_info = True
            settings_db.objects.filter(setting_id=setting_id).update(
                setting_status=openvas_info
            )
        except:
            openvas_info = False
            settings_db.objects.filter(setting_id=setting_id).update(
                setting_status=openvas_info
            )

        return HttpResponseRedirect(reverse("archerysettings:settings"))

    return render(
        request,
        "networkscanners/setting_form.html",
    )


def openvas_setting(request):
    username = request.user.username
    """
    Calling OpenVAS setting page.
    :param request:
    :return:
    """
    load_openvas_setting = load_settings.ArcherySettings(api_data, username=username)
    openvas_host = load_openvas_setting.openvas_host()
    openvas_port = load_openvas_setting.openvas_port()
    openvas_enabled = load_openvas_setting.openvas_enabled()
    if openvas_enabled:
        openvas_enabled = "True"
    else:
        openvas_enabled = "False"
    openvas_user = load_openvas_setting.openvas_username()
    openvas_password = load_openvas_setting.openvas_pass()
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


def xml_upload(request):
    username = request.user.username
    """
    OpenVAS XML file upload.
    :param request:
    :return:
    """
    all_project = project_db.objects.filter(username=username)
    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES["xmlfile"]
        scan_ip = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "openvas":
            date_time = datetime.now()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            hosts = OpenVas_Parser.get_hosts(root_xml)
            for host in hosts:
                scan_dump = NetworkScanDb(
                    ip=host,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    username=username,
                    scanner='Openvas'
                )
                scan_dump.save()
            OpenVas_Parser.updated_xml_parser(
                project_id=project_id, scan_id=scan_id, root=root_xml, username=username
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))
        elif scanner == "nessus":
            date_time = datetime.now()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            Nessus_Parser.updated_nessus_parser(
                root=root_xml,
                scan_id=scan_id,
                project_id=project_id,
                username=username,
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("nessus:nessus_list"))
        elif scanner == "nmap":
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            nmap_parser.xml_parser(
                root=root_xml,
                scan_id=scan_id,
                project_id=project_id,
                username=username,
            )
            messages.success(request, "File Uploaded")
            return HttpResponseRedirect(reverse("tools:nmap_scan"))

    return render(request, "networkscanners/net_upload_xml.html", {"all_project": all_project})


@background(schedule=60)
def task(target_ip, project_id, scanner):
    rescan_id = ""
    rescan = "No"
    sel_profile = ""
    ip = target_ip.replace(" ", "")
    target__split = ip.split(",")
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        if scanner == "open_vas":
            thread = threading.Thread(
                target=openvas_scanner, args=(target, project_id, sel_profile)
            )
            thread.daemon = True
            thread.start()

        return HttpResponse(status=200)


def net_scan_schedule(request):
    """

    :param request:
    :return:
    """
    task_id = ''
    username = request.user.username
    all_scans_db = project_db.objects.filter(username=username)
    all_scheduled_scans = task_schedule_db.objects.filter(username=username)

    if request.method == "POST":
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

            save_scheadule = task_schedule_db(
                task_id=task_id,
                target=target,
                schedule_time=scan_schedule_time,
                project_id=project_id,
                scanner=scanner,
                periodic_task=periodic_task_value,
                username=username,
            )
            save_scheadule.save()

    return render(
        request,
        "networkscanners/network_scan_schedule.html",
        {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
    )


def del_net_scan_schedule(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == "POST":
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(
                username=username, task_id=task_id
            )
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id)
            del_task_schedule.delete()

    return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))


def nv_setting(request):
    username = request.user.username
    """
    Calling NMAP Vulners setting page.
    :param request:
    :return:
    """
    load_nv_setting = load_settings.ArcherySettings(api_data, username=username)
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


def nv_details(request):
    username = request.user.username
    """
    OpenVAS tool settings.
    :param request:
    :return:
    """
    save_nv_setting = save_settings.SaveSettings(api_data, username=username)
    if request.method == "POST":
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

        return HttpResponseRedirect(reverse("webscanners:setting"))

    return render(
        request,
        "networkscanners/nv_settings.html",
        {
            "messages": messages,
        },
    )
