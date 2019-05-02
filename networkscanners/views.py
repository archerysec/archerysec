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
import os
import threading
import time
import uuid
import defusedxml.ElementTree as ET
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render, render_to_response, HttpResponse
from django.utils import timezone
from archerysettings import save_settings
from archerysettings import load_settings
from networkscanners.models import scan_save_db, \
    ov_scan_result_db, \
    task_schedule_db, \
    nessus_scan_db, nessus_report_db
from projects.models import project_db
from scanners.scanner_parser.network_scanner import OpenVas_Parser, Nessus_Parser, nmap_parser
from scanners.scanner_plugin.network_scanner.openvas_plugin import OpenVAS_Plugin, vuln_an_id
from background_task.models import Task
from background_task import background
from datetime import datetime
from jiraticketing.models import jirasetting
import hashlib
import json

from django.contrib.auth.models import User
from notifications.signals import notify
from notifications.models import Notification
from django.core.mail import send_mail
from django.conf import settings
from archerysettings.models import email_db

from notifications.models import Notification

api_data = os.getcwd() + '/' + 'apidata.json'

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
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb='Email Settings Not Configured')
        pass


def index(request):
    """
    Function calling network base html.
    :param request:
    :return:
    """
    all_ip = scan_save_db.objects.all()

    all_notify = Notification.objects.unread()

    return render(request, 'openvas_scan.html', {'all_ip': all_ip, 'message': all_notify})


def scan_status(request):
    """
    Check the network scan status.
    :param request:
    :return:
    """
    if request.method == 'POST':
        all_ip = scan_save_db.objects.all()
        scan_ip = request.POST.get('scan_id', )

    return render(request, 'openvas_scan.html')


def scan_vul_details(request):
    """
    Get the Network scan vulnerability details.
    :param request:
    :return:
    """
    jira_url = None
    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server
    scanid = ""
    if request.method == 'GET':
        scanid = request.GET['scan_id']


    if request.method == 'POST':
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        false_positive = request.POST.get('false')
        status = request.POST.get('status')

        ov_scan_result_db.objects.filter(
            scan_id=scan_id,
            vul_id=vuln_id).update(
            false_positive=false_positive, vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = ov_scan_result_db.objects.filter(scan_id=scan_id, vul_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                host = vi.host
                severity = vi.severity
                port = vi.port
                dup_data = name + host + severity + port
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                ov_scan_result_db.objects.filter(
                    scan_id=scan_id,
                    vul_id=vuln_id).update(
                    false_positive=false_positive,
                    vuln_status=status,
                    false_positive_hash=false_positive_hash
                )

        return HttpResponseRedirect(
            '/networkscanners/vul_details/?scan_id=%s' % scan_id)

    all_vuln = ov_scan_result_db.objects.filter(scan_id=scanid,
                                                false_positive='No', vuln_status='Open').values('name', 'severity',
                                                                                                'vuln_color',
                                                                                                'threat', 'host',
                                                                                                'port', 'vul_id',
                                                                                                'jira_ticket',
                                                                                                'vuln_status').distinct()

    all_vuln_closed = ov_scan_result_db.objects.filter(scan_id=scanid,
                                                       false_positive='No', vuln_status='Closed').values('name',
                                                                                                         'severity',
                                                                                                         'vuln_color',
                                                                                                         'threat',
                                                                                                         'host',
                                                                                                         'port',
                                                                                                         'vul_id',
                                                                                                         'jira_ticket',
                                                                                                         'vuln_status'
                                                                                                         ).distinct()

    all_false_vul = ov_scan_result_db.objects.filter(scan_id=scanid,
                                                     false_positive='Yes').values('name', 'severity',
                                                                                  'vuln_color',
                                                                                  'threat', 'host',
                                                                                  'port', 'vul_id',
                                                                                  'jira_ticket').distinct()
    return render(request,
                  'openvas_vuln_list.html',
                  {'all_vuln': all_vuln,
                   'scan_id': scanid,
                   'jira_url': jira_url,
                   'all_false_vul': all_false_vul,
                   'all_vuln_closed': all_vuln_closed
                   })


def openvas_scanner(scan_ip, project_id, sel_profile, user):
    """
    The function is launch the OpenVAS scans.
    :param scan_ip:
    :param project_id:
    :param sel_profile:
    :return:
    """
    openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile)
    try:
        scanner = openvas.connect()
    except Exception as e:

        notify.send(user, recipient=user, verb='OpenVAS Setting not configured')
        subject = 'Archery Tool Notification'
        message = 'OpenVAS Scanner failed due to setting not found '

        email_notify(user=user, subject=subject, message=message)
        return

    notify.send(user, recipient=user, verb='OpenVAS Scan Started')
    subject = 'Archery Tool Notification'
    message = 'OpenVAS Scan Started'

    email_notify(user=user, subject=subject, message=message)
    scan_id, target_id = openvas.scan_launch(scanner)
    date_time = datetime.now()
    save_all = scan_save_db(scan_id=str(scan_id),
                            project_id=str(project_id),
                            scan_ip=scan_ip,
                            target_id=str(target_id),
                            date_time=date_time,
                            scan_status=0.0)
    save_all.save()
    openvas.scan_status(scanner=scanner, scan_id=scan_id)
    time.sleep(5)
    vuln_an_id(scan_id=scan_id, project_id=project_id)

    notify.send(user, recipient=user, verb='OpenVAS Scan Completed')

    all_openvas = scan_save_db.objects.all()
    all_vuln = ''
    total_high = ''
    total_medium = ''
    total_low = ''
    for openvas in all_openvas:
        all_vuln = openvas.total_vul
        total_high = openvas.high_total
        total_medium = openvas.medium_total
        total_low = openvas.low_total

    subject = 'Archery Tool Notification'
    message = 'OpenVAS Scan Completed  <br>' \
              'Total: %s  <br>Total High: %s <br>' \
              'Total Medium: %s  <br>Total Low %s' % (all_vuln, total_high, total_medium, total_low)

    email_notify(user=user, subject=subject, message=message)

    return HttpResponse(status=201)


def launch_scan(request):
    """
    Function Trigger Network scans.
    :param request:
    :return:
    """
    all_ip = scan_save_db.objects.all()
    user = request.user

    if request.method == 'POST':
        all_ip = scan_save_db.objects.all()
        scan_ip = request.POST.get('ip')
        project_id = request.POST.get('project_id')
        sel_profile = request.POST.get('scan_profile')
        ip = scan_ip.replace(" ", "")
        target_split = ip.split(',')
        split_length = target_split.__len__()

        for i in range(0, split_length):
            target = target_split.__getitem__(i)

            thread = threading.Thread(target=openvas_scanner, args=(target, project_id, sel_profile, user))
            thread.daemon = True
            thread.start()

    return render_to_response('openvas_vuln_list.html',
                              {'all_ip': all_ip})


def scan_del(request):
    """
    Delete Network scans.
    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            scans = scan_save_db.objects.filter(scan_id=scan_id).order_by('scan_id')
            scans.delete()
            vuln_data = ov_scan_result_db.objects.filter(scan_id=scan_id)
            vuln_data.delete()

    return HttpResponseRedirect("/networkscanners/")


def ip_scan(request):
    """
    List all network scan IP's.
    :param request:
    :return:
    """
    all_scans = scan_save_db.objects.all()
    all_proj = project_db.objects.all()

    all_notify = Notification.objects.unread()

    return render(request,
                  'ipscan.html',
                  {'all_scans': all_scans,
                   'all_proj': all_proj,
                   'message': all_notify,
                   })


def ip_scan_table(request):
    """
    Network scan Table.
    :param request:
    :return:
    """
    all_scans = scan_save_db.objects.all()

    return render(request, 'ip_scan_table.html', {'all_scans': all_scans})


def openvas_details(request):
    """
    OpenVAS tool settings.
    :param request:
    :return:
    """
    save_openvas_setting = save_settings.SaveSettings(api_data)
    if request.method == 'POST':
        if request.POST.get("openvas_enabled") == 'on':
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
        )

        return HttpResponseRedirect('/webscanners/setting/')

    messages.add_message(request,
                         messages.SUCCESS,
                         'Openvas Setting Updated ')

    return render(request, 'setting_form.html', )


def openvas_setting(request):
    """
    Calling OpenVAS setting page.
    :param request:
    :return:
    """
    load_openvas_setting = load_settings.ArcherySettings(api_data)
    openvas_host = load_openvas_setting.openvas_host()
    openvas_port = load_openvas_setting.openvas_port()
    openvas_enabled = load_openvas_setting.openvas_enabled()
    if openvas_enabled:
        openvas_enabled = 'True'
    else:
        openvas_enabled = 'False'
    openvas_user = load_openvas_setting.openvas_username()
    openvas_password = load_openvas_setting.openvas_pass()
    return render(request,
                  'setting_form.html',
                  {
                      'openvas_host': openvas_host,
                      'openvas_port': openvas_port,
                      'openvas_enabled': openvas_enabled,
                      'openvas_user': openvas_user,
                      'openvas_password': openvas_password
                  }
                  )


def del_vuln(request):
    """
    Delete Network Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln")
        un_scanid = request.POST.get("scan_id")


        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()

        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = ov_scan_result_db.objects.filter(vul_id=vuln_id)
            delete_vuln.delete()
        ov_all_vul = ov_scan_result_db.objects.filter(scan_id=un_scanid).order_by('scan_id')
        total_vul = len(ov_all_vul)
        total_high = len(ov_all_vul.filter(threat="High"))
        total_medium = len(ov_all_vul.filter(threat="Medium"))
        total_low = len(ov_all_vul.filter(threat="Low"))

        scan_save_db.objects.filter(scan_id=un_scanid) \
            .update(total_vul=total_vul,
                    high_total=total_high,
                    medium_total=total_medium,
                    low_total=total_low)
        # messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/networkscanners/vul_details/?scan_id=%s" % un_scanid)


def edit_vuln(request):
    """
    Edit Network scan vulnerabilities.
    :param request:
    :return:
    """
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        vul_id = request.POST.get("vuln_id")
        name = request.POST.get("name")
        creation_time = request.POST.get("creation_time")
        modification_time = request.POST.get("modification_time")
        host = request.POST.get("host")
        port = request.POST.get("port")
        threat = request.POST.get("threat")
        severity = request.POST.get("severity")
        description = request.POST.get("description")
        family = request.POST.get("family")
        cvss_base = request.POST.get("cvss_base")
        cve = request.POST.get("cve")
        # bid = request.POST.get("bid")
        xref = request.POST.get("xref")
        tags = request.POST.get("tags")
        banner = request.POST.get("banner")

        ov_scan_result_db.objects.filter(vul_id=vul_id).update(name=name,
                                                               creation_time=creation_time,
                                                               modification_time=modification_time,
                                                               host=host, port=port,
                                                               threat=threat,
                                                               severity=severity,
                                                               description=description, family=family,
                                                               cvss_base=cvss_base, cve=cve,
                                                               xref=xref, tags=tags, banner=banner)

        messages.success(request, "Vulnerability Edited")

        return HttpResponseRedirect("/networkscanners/vul_details/?scan_id=%s" % scan_id)

    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    edit_vul_dat = ov_scan_result_db.objects.filter(vul_id=id_vul).order_by('vul_id')

    return render(request, 'ov_edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def vuln_check(request):
    """
    Get the detailed vulnerability information.
    :param request:
    :return:
    """
    global cve_list
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    vul_dat = ov_scan_result_db.objects.filter(vul_id=id_vul).order_by('vul_id')

    for cve_dat in vul_dat:
        cve = cve_dat.cve
        xref = cve_dat.xref
        xref_list = xref.split(",")
        cve_list = cve.split(",")

    return render(request, 'openvas_scan_data.html', {'vul_dat': vul_dat,
                                                 'cve_list': cve_list,
                                                 'xref_list': xref_list

                                                 })


def add_vuln(request):
    """
    Add network vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = ''

    if request.method == 'POST':
        vuln_id = uuid.uuid4()
        scan_id = request.POST.get("scan_id")
        name = request.POST.get("name")
        creation_time = request.POST.get("creation_time")
        modification_time = request.POST.get("modification_time")
        host = request.POST.get("host")
        port = request.POST.get("port", )
        threat = request.POST.get("threat", )
        severity = request.POST.get("severity", )
        description = request.POST.get("description", )
        family = request.POST.get("family", )
        cvss_base = request.POST.get("cvss_base", )
        cve = request.POST.get("cve", )
        # bid = request.POST.get("bid")
        xref = request.POST.get("xref", )
        tags = request.POST.get("tags", )
        banner = request.POST.get("banner", )

        save_vuln = ov_scan_result_db(name=name,
                                      vul_id=vuln_id,
                                      scan_id=scan_id,
                                      creation_time=creation_time,
                                      modification_time=modification_time,
                                      host=host, port=port,
                                      threat=threat,
                                      severity=severity,
                                      description=description,
                                      family=family,
                                      cvss_base=cvss_base,
                                      cve=cve,
                                      xref=xref,
                                      tags=tags,
                                      banner=banner,
                                      false_positive='No',
                                      )
        save_vuln.save()

        messages.success(request, "Vulnerability Added")
        return HttpResponseRedirect("/networkscanners/?scan_id=%s" % scan_id)

    return render(request, 'ov_add_vuln.html', {'scan_id': scan_id})


def OpenVAS_xml_upload(request):
    """
    OpenVAS XML file upload.
    :param request:
    :return:
    """
    all_project = project_db.objects.all()
    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES['xmlfile']
        scan_ip = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "openvas":
            date_time = datetime.now()
            scan_dump = scan_save_db(scan_ip=scan_ip,
                                     scan_id=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            OpenVas_Parser.xml_parser(project_id=project_id,
                                      scan_id=scan_id,
                                      root=root_xml)
            return HttpResponseRedirect("/networkscanners/")
        elif scanner == "nessus":
            date_time = datetime.now()
            scan_dump = nessus_scan_db(
                scan_ip=scan_ip,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            Nessus_Parser.nessus_parser(root=root_xml,
                                        scan_id=scan_id,
                                        project_id=project_id,
                                        )
            return HttpResponseRedirect("/networkscanners/nessus_scan")
        elif scanner == "nmap":
            # date_time = datetime.now()
            # scan_dump = nessus_scan_db(
            #     scan_ip=scan_ip,
            #     scan_id=scan_id,
            #     date_time=date_time,
            #     project_id=project_id,
            #     scan_status=scan_status
            # )
            # scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            nmap_parser.xml_parser(root=root_xml,
                                   scan_id=scan_id,
                                   project_id=project_id,
                                   )
            return HttpResponseRedirect("/tools/nmap_scan/")

    return render(request,
                  'net_upload_xml.html',
                  {'all_project': all_project})


@background(schedule=60)
def task(target_ip, project_id, scanner):
    rescan_id = ''
    rescan = 'No'
    sel_profile = ''
    ip = target_ip.replace(" ", "")
    target__split = ip.split(',')
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        if scanner == 'open_vas':
            thread = threading.Thread(target=openvas_scanner, args=(target, project_id, sel_profile))
            thread.daemon = True
            thread.start()

        return HttpResponse(status=200)


def net_scan_schedule(request):
    """

    :param request:
    :return:
    """
    all_scans_db = project_db.objects.all()
    all_scheduled_scans = task_schedule_db.objects.all()

    if request.method == 'POST':
        scan_ip = request.POST.get('ip')
        scan_schedule_time = request.POST.get('datetime')
        project_id = request.POST.get('project_id')
        scanner = request.POST.get('scanner')
        # periodic_task = request.POST.get('periodic_task')
        periodic_task_value = request.POST.get('periodic_task_value')
        # periodic_task = 'Yes'


        if periodic_task_value == 'HOURLY':
            periodic_time = Task.HOURLY
        elif periodic_task_value == 'DAILY':
            periodic_time = Task.DAILY
        elif periodic_task_value == 'WEEKLY':
            periodic_time = Task.WEEKLY
        elif periodic_task_value == 'EVERY_2_WEEKS':
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == 'EVERY_4_WEEKS':
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None

        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, '%d/%m/%Y %H:%M:%S %p')

        # task(scan_ip, project_id, schedule=dt_obj)
        ip = scan_ip.replace(" ", "")
        target__split = ip.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == 'open_vas':
                if periodic_task_value == 'None':
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id
                else:
                    my_task = task(target, project_id, scanner, repeat=periodic_time, repeat_until=None)
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id

            save_scheadule = task_schedule_db(task_id=task_id, target=target,
                                              schedule_time=scan_schedule_time,
                                              project_id=project_id,
                                              scanner=scanner,
                                              periodic_task=periodic_task_value)
            save_scheadule.save()

    return render(request, 'network_scan_schedule.html',
                  {'all_scans_db': all_scans_db,
                   'all_scheduled_scans': all_scheduled_scans}
                  )


def del_net_scan_schedule(request):
    """

    :param request:
    :return:
    """

    if request.method == "POST":
        task_id = request.POST.get('task_id')

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(',')
        split_length = target_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(task_id=task_id)
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id)
            del_task_schedule.delete()

    return HttpResponseRedirect('/networkscanners/net_scan_schedule')


def nessus_scan(request):
    """

    :param request:
    :return:
    """
    all_scan = nessus_scan_db.objects.all()

    return render(request,
                  'nessus_scan.html',
                  {'all_scan': all_scan}
                  )


def nessus_vuln_details(request):
    """

    :param request:
    :return:
    """
    jira_url = None
    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    scanid = ""
    if request.method == 'GET':
        scanid = request.GET['scan_id']
    print("scansss"), scanid

    if request.method == 'POST':
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        false_positive = request.POST.get('false')
        status = request.POST.get('status')

        nessus_report_db.objects.filter(scan_id=scan_id,
                                        vul_id=vuln_id).update(false_positive=false_positive, vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = nessus_report_db.objects.filter(scan_id=scan_id, vul_id=vuln_id)
            for vi in vuln_info:
                scan_ip = vi.scan_ip
                plugin_name = vi.plugin_name
                severity = vi.severity
                port = vi.port
                dup_data = scan_ip + plugin_name + severity + port
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                nessus_report_db.objects.filter(scan_id=scan_id,
                                                vul_id=vuln_id).update(false_positive=false_positive,
                                                                       vuln_status=status,
                                                                       false_positive_hash=false_positive_hash)

        return HttpResponseRedirect(
            '/networkscanners/nessus_vuln_details/?scan_id=%s' % scan_id)

    all_vuln = nessus_report_db.objects.filter(scan_id=scanid,
                                               false_positive='No')

    all_vuln_closed = nessus_report_db.objects.filter(scan_id=scanid, vuln_status='Closed',
                                                      false_positive='No')

    all_false_vul = nessus_report_db.objects.filter(scan_id=scanid,
                                                    false_positive='Yes')
    return render(request,
                  'nessus_vuln_details.html',
                  {'all_vuln': all_vuln,
                   'scan_id': scanid,
                   'jira_url': jira_url,
                   'all_false_vul': all_false_vul,
                   'all_vuln_closed': all_vuln_closed
                   })


def delete_nessus_scan(request):
    if request.method == "POST":
        scan_id = request.POST.get('scan_id')
        del_vuln = request.POST.get('del_vuln')

        scan_item = str(scan_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(',')
        split_length = target_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)

            del_rep = nessus_report_db.objects.filter(scan_id=task_id)
            del_rep.delete()
            del_scan = nessus_scan_db.objects.filter(scan_id=task_id)
            del_scan.delete()

    return HttpResponseRedirect('/networkscanners/nessus_scan')


def delete_nessus_vuln(request):
    if request.method == "POST":
        vuln_id = request.POST.get("del_vuln")
        un_scanid = request.POST.get("scan_id")
        print("scan_iddd"), un_scanid

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = nessus_report_db.objects.filter(vul_id=vuln_id)
            delete_vuln.delete()
        ov_all_vul = nessus_report_db.objects.filter(scan_id=un_scanid).order_by('scan_id')
        total_vul = len(ov_all_vul)
        total_critical = len(ov_all_vul.filter(risk_factor="Critical"))
        total_high = len(ov_all_vul.filter(risk_factor="High"))
        total_medium = len(ov_all_vul.filter(risk_factor="Medium"))
        total_low = len(ov_all_vul.filter(risk_factor="Low"))

        nessus_scan_db.objects.filter(scan_id=un_scanid) \
            .update(total_vul=total_vul,
                    critical_total=total_critical,
                    high_total=total_high,
                    medium_total=total_medium,
                    low_total=total_low)
        # messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/networkscanners/nessus_vuln_details/?scan_id=%s" % un_scanid)


def nessus_vuln_check(request):
    """
    Get the detailed vulnerability information.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    vul_dat = nessus_report_db.objects.filter(vul_id=id_vul)

    return render(request, 'nessus_vuln_data.html', {'vul_dat': vul_dat})


def nv_setting(request):
    """
    Calling NMAP Vulners setting page.
    :param request:
    :return:
    """
    load_nv_setting = load_settings.ArcherySettings(api_data)
    nv_enabled = str(load_nv_setting.nv_enabled())
    nv_online = str(load_nv_setting.nv_enabled())
    nv_version = str(load_nv_setting.nv_enabled())
    nv_timing = load_nv_setting.nv_timing()

    return render(request,
                  'nv_settings.html',
                  {
                      'nv_enabled': nv_enabled,
                      'nv_online': nv_online,
                      'nv_version': nv_version,
                      'nv_timing': nv_timing,
                  }
                  )


def nv_details(request):
    """
    OpenVAS tool settings.
    :param request:
    :return:
    """
    save_nv_setting = save_settings.SaveSettings(api_data)
    if request.method == 'POST':
        if str(request.POST.get("nv_enabled")) == 'on':
            nv_enabled = True
        else:
            nv_enabled = False
        if str(request.POST.get("nv_online")) == 'on':
            nv_online = True
        else:
            nv_online = False
        if str(request.POST.get("nv_version")) == 'on':
            nv_version = True
        else:
            nv_version = False
        nv_timing = int(str(request.POST.get('nv_timing')))
        if nv_timing > 5:
            nv_timing = 5
        elif nv_timing < 0:
            nv_timing = 0

        save_nv_setting.nmap_vulners(
            enabled=nv_enabled,
            version=nv_version,
            online=nv_online,
            timing=nv_timing
        )

        return HttpResponseRedirect('/webscanners/setting/')

    messages.add_message(request,
                         messages.SUCCESS,
                         'NMAP Vulners Setting Updated ')

    return render(request,
                  'nv_settings.html',
                  {
                      'messages': messages,
                  })
