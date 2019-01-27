#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from __future__ import unicode_literals
import threading
import time
import uuid
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from scanners.scanner_plugin.web_scanner import burp_plugin
from webscanners.models import burp_scan_db, burp_scan_result_db
from datetime import datetime
from jiraticketing.models import jirasetting
from archerysettings.models import burp_setting_db
import hashlib
from webscanners.resources import BurpResource


def burp_setting(request):
    """
    Load Burp Settings.
    :param request:
    :return:
    """
    burp_url = None
    burp_port = None
    all_burp_setting = burp_setting_db.objects.all()

    for data in all_burp_setting:
        global burp_url, burp_port
        burp_url = data.burp_url
        burp_port = data.burp_port

    if request.method == 'POST':
        burphost = request.POST.get("burpath")
        burport = request.POST.get("burport")
        save_burp_settings = burp_setting_db(burp_url=burphost, burp_port=burport)
        save_burp_settings.save()

        return HttpResponseRedirect('/burpscanner/setting/')

    return render(request, 'burpscanner/burp_setting_form.html', {'burp_url': burp_url, 'burp_port': burp_port})


def burp_scan_launch(request):
    """
    Burp Scan Trigger.
    :param request:
    :return:
    """
    global vuln_id, burp_status
    if request.POST.get("url"):
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        target__split = target_url.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print "Targets", target
            scan_id = uuid.uuid4()
            date_time = datetime.now()
            scan_dump = burp_scan_db(scan_id=scan_id,
                                     project_id=project_id,
                                     url=target,
                                     date_time=date_time)
            scan_dump.save()
            try:
                do_scan = burp_plugin.burp_scans(
                    project_id,
                    target,
                    scan_id)
                # do_scan.scan_lauch(project_id,
                #                    target,
                #                    scan_id)

                thread = threading.Thread(
                    target=do_scan.scan_launch,
                )
                thread.daemon = True
                thread.start()
                time.sleep(5)
            except Exception as e:
                print e

    return render(request, 'burpscanner/burp_scan_list.html')


def burp_scan_list(request):
    """
    List all burp scans.
    :param request:
    :return:
    """
    all_burp_scan = burp_scan_db.objects.all()

    return render(request,
                  'burpscanner/burp_scan_list.html',
                  {'all_burp_scan': all_burp_scan})


def burp_list_vuln(request):
    """
    List all Burp Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None
    burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                      vuln_status='Open').values('name',
                                                                                 'severity',
                                                                                 'severity_color',
                                                                                 'scan_id').distinct()

    burp_all_vul_close = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                            vuln_status='Closed').values('name',
                                                                                         'severity',
                                                                                         'severity_color',
                                                                                         'scan_id').distinct()

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
    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']
    else:
        vuln_id = None
    vuln_data = burp_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request,
                  'burpscanner/burp_vuln_data.html',
                  {'vuln_data': vuln_data})


def burp_vuln_out(request):
    """
    The function calling burp vulnerability details.
    :param request:
    :return:
    """
    jira_url = None
    jira = jirasetting.objects.all()
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
        burp_scan_result_db.objects.filter(vuln_id=vuln_id,
                                           scan_id=scan_id).update(false_positive=false_positive,
                                                                   vuln_status=vuln_status)

        if false_positive == 'Yes':
            vuln_info = burp_scan_result_db.objects.filter(scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                location = vi.location
                severity = vi.severity
                dup_data = name + location + severity
                false_positive_hash = hashlib.sha256(dup_data).hexdigest()
                burp_scan_result_db.objects.filter(vuln_id=vuln_id,
                                                   scan_id=scan_id).update(false_positive=false_positive,
                                                                           vuln_status=vuln_status,
                                                                           false_positive_hash=false_positive_hash
                                                                           )

        messages.add_message(request,
                             messages.SUCCESS,
                             'Vulnerability Status Changed')
        return HttpResponseRedirect(
            '/burpscanner/burp_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id,
                                                                     vuln_name))
    vuln_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                   name=name,
                                                   false_positive='No',
                                                   vuln_status='Open'
                                                   )
    vuln_close_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                         name=name,
                                                         false_positive='No',
                                                         vuln_status='Closed'
                                                         )

    false_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
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
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = burp_scan_db.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = burp_scan_result_db.objects.filter(scan_id=scan_id)
            item_results.delete()
            messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/burpscanner/burp_scan_list/')


def del_burp_vuln(request):
    """
    Delete Vulnerability from database.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = burp_scan_result_db.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        burp_all_vul = burp_scan_result_db.objects.filter(scan_id=un_scanid).values('name', 'severity',
                                                                                    'severity_color').distinct()
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))

        burp_scan_db.objects.filter(scan_id=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                              medium_vul=total_medium, low_vul=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/burpscanner/burp_vuln_list?scan_id=%s" % un_scanid)


def edit_burp_vuln(request):
    """
    Edit Burp vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    edit_vul_dat = burp_scan_result_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id", )
        scan_id = request.POST.get("scan_id", )
        name = request.POST.get("name", )
        severity = request.POST.get("severity", )
        host = request.POST.get("host", )
        path = request.POST.get("path", )
        issuedetail = request.POST.get("issuedetail")
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )
        location = request.POST.get("location", )
        vulnClass = request.POST.get("reference", )

        global vul_col

        if severity == 'High':
            vul_col = "important"
        elif severity == 'Medium':
            vul_col = "warning"
        elif severity == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"

        print "edit_vul :", name

        burp_scan_result_db.objects.filter(
            vuln_id=vuln_id).update(name=name,
                                    severity_color=vul_col,
                                    severity=severity,
                                    host=host, path=path,
                                    location=location,
                                    issueDetail=issuedetail,
                                    issueBackground=description,
                                    remediationBackground=solution,
                                    vulnerabilityClassifications=vulnClass)
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/burpscanner/burp_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'burpscanner/edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def export(request):
    """
    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        zap_resource = BurpResource()
        queryset = burp_scan_result_db.objects.filter(scan_id=scan_id)
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
