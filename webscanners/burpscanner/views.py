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
import threading
import time
import uuid
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from scanners.scanner_plugin.web_scanner import burp_plugin
from webscanners.models import burp_scan_db, burp_scan_result_db, burp_issue_definitions
from datetime import datetime
from jiraticketing.models import jirasetting
from archerysettings.models import burp_setting_db
import hashlib
from webscanners.resources import BurpResource
from notifications.models import Notification
from PyBurprestapi import burpscanner
import json
from notifications.signals import notify
from django.urls import reverse

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
        global burp_url, burp_port, burp_api_key, \
            remediation, issue_type_id, description, \
            name, references, \
            vulnerability_classifications
        burp_url = data.burp_url
        burp_port = data.burp_port
        burp_api_key = data.burp_api_key

    if request.method == 'POST':
        burphost = request.POST.get("burpath")
        burport = request.POST.get("burport")
        burpapikey = request.POST.get("burpapikey")
        save_burp_settings = burp_setting_db(username=username, burp_url=burphost, burp_port=burport,
                                             burp_api_key=burpapikey)
        save_burp_settings.save()

        host = 'http://' + burphost + ':' + burport + '/'

        bi = burpscanner.BurpApi(host, burpapikey)

        issue_list = bi.issue_definitions()

        json_issue_data = json.dumps(issue_list.data)
        issues = json.loads(json_issue_data)

        all_data = burp_issue_definitions.objects.filter(username=username)
        all_data.delete()

        try:
            for issue_dat in issues:
                for key, values in issue_dat.items():
                    if key == 'remediation':
                        remediation = values
                    if key == 'issue_type_id':
                        issue_type_id = values
                    if key == 'description':
                        description = values
                    if key == 'name':
                        name = values
                    if key == 'references':
                        references = values
                    if key == 'vulnerability_classifications':
                        vulnerability_classifications = values

                data_dump = burp_issue_definitions(username=username,
                                                   remediation=remediation,
                                                   issue_type_id=issue_type_id,
                                                   description=description,
                                                   reference=references,
                                                   vulnerability_classifications=vulnerability_classifications,
                                                   name=name
                                                   )
                data_dump.save()
        except Exception as e:
            print(e)
            notify.send(user, recipient=user, verb='Burp Connection Not Found')

        return HttpResponseRedirect(reverse('webscanners:setting'))

    return render(request, 'burpscanner/burp_setting_form.html',
                  {'burp_url': burp_url,
                   'burp_port': burp_port,
                   'burp_api_key': burp_api_key
                   })


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
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        target__split = target_url.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print("Targets"), target
            scan_id = uuid.uuid4()
            try:
                do_scan = burp_plugin.burp_scans(
                    project_id,
                    target,
                    scan_id,
                    user
                )

                thread = threading.Thread(
                    target=do_scan.scan_launch,
                )
                thread.daemon = True
                thread.start()
                time.sleep(5)
            except Exception as e:
                print(e)

    return render(request, 'burpscanner/burp_scan_list.html')


def burp_scan_list(request):
    """
    List all burp scans.
    :param request:
    :return:
    """
    username = request.user.username
    all_burp_scan = burp_scan_db.objects.filter(username=username)

    return render(request,
                  'burpscanner/burp_scan_list.html',
                  {'all_burp_scan': all_burp_scan})


def burp_list_vuln(request):
    """
    List all Burp Vulnerability.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None
    burp_all_vul = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id,
                                                      ).values('name',
                                                               'severity',
                                                               'severity_color',
                                                               'vuln_status',
                                                               'scan_id').distinct().exclude(vuln_status='Duplicate')

    burp_all_vul_close = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id,
                                                            ).values('name',
                                                                     'severity',
                                                                     'severity_color',
                                                                     'vuln_status',
                                                                     'scan_id').distinct().exclude(vuln_status='Duplicate')

    return render(request,
                  'burpscanner/burp_list_vuln.html',
                  {'burp_all_vul': burp_all_vul,
                   'scan_id': scan_id,
                   'burp_all_vul_close': burp_all_vul_close
                   })


def burp_vuln_data(request):
    """
    Add Burp Vulnerability.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']
    else:
        vuln_id = None
    vuln_data = burp_scan_result_db.objects.filter(username=username, vuln_id=vuln_id)

    return render(request,
                  'burpscanner/burp_vuln_data.html',
                  {'vuln_data': vuln_data})


def burp_vuln_out(request):
    """
    The function calling burp vulnerability details.
    :param request:
    :return:
    """
    username = request.user.username
    jira_url = None
    jira = jirasetting.objects.filter(username=username)
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        name = request.GET['scan_name']
    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        burp_scan_result_db.objects.filter(username=username, vuln_id=vuln_id,
                                           scan_id=scan_id).update(false_positive=false_positive,
                                                                   vuln_status=vuln_status)

        if false_positive == 'Yes':
            vuln_info = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                location = vi.path
                severity = vi.severity
                dup_data = name + location + severity
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                burp_scan_result_db.objects.filter(username=username, vuln_id=vuln_id,
                                                   scan_id=scan_id).update(false_positive=false_positive,
                                                                           vuln_status='Close',
                                                                           false_positive_hash=false_positive_hash
                                                                           )
        burp_all_vul = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                          vuln_status='Open')
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))
        total_info = len(burp_all_vul.filter(severity="Information"))
        total_duplicate = len(burp_all_vul.filter(vuln_duplicate='Yes'))
        burp_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_duplicate
        )

        return HttpResponseRedirect(
            reverse('burpscanner:burp_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id,
                                                                                 vuln_name))
    vuln_data = burp_scan_result_db.objects.filter(username=username,
                                                   scan_id=scan_id,
                                                   name=name,
                                                   false_positive='No',
                                                   vuln_status='Open'
                                                   )
    vuln_close_data = burp_scan_result_db.objects.filter(username=username,
                                                         scan_id=scan_id,
                                                         name=name,
                                                         false_positive='No',
                                                         vuln_status='Closed'
                                                         )

    false_data = burp_scan_result_db.objects.filter(username=username,
                                                    scan_id=scan_id,
                                                    name=name,
                                                    false_positive='Yes')

    return render(request, 'burpscanner/burp_vuln_out.html', {'vuln_data': vuln_data,
                                                              'false_data': false_data,
                                                              'jira_url': jira_url,
                                                              'vuln_close_data': vuln_close_data
                                                              })


def del_burp_scan(request):
    """
    Delete Burp scans.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = burp_scan_db.objects.filter(username=username,
                                               scan_id=scan_id)
            item.delete()
            item_results = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse('burpscanner:burp_scan_list'))


def del_burp_vuln(request):
    """
    Delete Vulnerability from database.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = burp_scan_result_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        burp_all_vul = burp_scan_result_db.objects.filter(username=username, scan_id=un_scanid).values('name',
                                                                                                       'severity',
                                                                                                       'severity_color').distinct()
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))

        burp_scan_db.objects.filter(username=username, scan_id=un_scanid).update(total_vul=total_vul,
                                                                                 high_vul=total_high,
                                                                                 medium_vul=total_medium,
                                                                                 low_vul=total_low)

        return HttpResponseRedirect(reverse('burpscanner:burp_vuln_list') + '?scan_id=%s' % un_scanid)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        zap_resource = BurpResource()
        queryset = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id)
        dataset = zap_resource.export(queryset)
        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % scan_id
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % scan_id
            return response
        if report_type == 'yaml':
            response = HttpResponse(dataset.yaml, content_type='application/x-yaml')
            response['Content-Disposition'] = 'attachment; filename="%s.yaml"' % scan_id
            return response
