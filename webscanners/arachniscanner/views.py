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
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from webscanners.models import burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db
from jiraticketing.models import jirasetting
import hashlib
import PyArachniapi
from archerysettings.models import arachni_settings_db
import uuid
import threading
from datetime import datetime
import defusedxml.ElementTree as ET
from scanners.scanner_parser.web_scanner import arachni_xml_parser
import json
import time


def launch_arachni_scan(target, project_id, rescan_id, rescan, scan_id):
    arachni_hosts = None
    arachni_ports = None

    all_arachni = arachni_settings_db.objects.all()
    for arachni in all_arachni:
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port

    arachni = PyArachniapi.arachniAPI(arachni_hosts, arachni_ports)

    data = {"url": target, "checks": "*"}
    d = json.dumps(data)

    scan_launch = arachni.scan_launch(d)
    time.sleep(3)

    print("Scan Launched !!!!!")

    date_time = datetime.now()

    try:
        save_all_scan = arachni_scan_db(
            project_id=project_id,
            url=target,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
        )

        save_all_scan.save()

    except Exception as e:
        print e

    scan_data = scan_launch.data

    for key, value in scan_data.viewitems():
        if key == 'id':
            scan_run_id = value

    scan_sum = arachni.scan_summary(id=scan_run_id).data
    for key, value in scan_sum.viewitems():
        if key == 'status':
            scan_status = value
    while scan_status != 'done':
        status = '0'
        if scan_sum['statistics']['browser_cluster']['queued_job_count'] and scan_sum['statistics']['browser_cluster'][
            'total_job_time']:
            status = 100 - scan_sum['statistics']['browser_cluster']['queued_job_count'] * 100 / \
                     scan_sum['statistics']['browser_cluster']['total_job_time']
        arachni_scan_db.objects.filter(scan_id=scan_id).update(scan_status=status)
        scan_sum = arachni.scan_summary(id=scan_run_id).data
        for key, value in scan_sum.viewitems():
            if key == 'status':
                scan_status = value
        time.sleep(3)
    print "scan_di", scan_run_id
    if scan_status == 'done':
        xml_report = arachni.scan_xml_report(id=scan_run_id).data
        root_xml = ET.fromstring(xml_report)
        arachni_xml_parser.xml_parser(project_id=project_id,
                                      scan_id=scan_id,
                                      root=root_xml)
        arachni_scan_db.objects.filter(scan_id=scan_id).update(scan_status='100')
        print("Data uploaded !!!!")

    print scan_run_id


def arachni_scan(request):
    """
    The function trigger Arachni scan.
    :param request:
    :return:
    """
    if request.method == "POST":
        target_url = request.POST.get('scan_url')
        print target_url
        project_id = request.POST.get('project_id')
        rescan_id = None
        rescan = 'No'
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print "Targets -", target
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_arachni_scan,
                args=(target, project_id, rescan_id, rescan, scan_id))
            thread.daemon = True
            thread.start()

    return render(request,
                  'arachniscanner/arachni_scan_list.html')


def arachni_list_vuln(request):
    """
    Arachni Vulnerability List
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    arachni_all_vul = arachni_scan_result_db.objects.filter(
        scan_id=scan_id, vuln_status='Open').values('name',
                                                    'severity',
                                                    'vuln_color',
                                                    'scan_id').distinct()

    arachni_all_vul_close = arachni_scan_result_db.objects.filter(
        scan_id=scan_id, vuln_status='Closed').values('name',
                                                      'severity',
                                                      'vuln_color',
                                                      'scan_id').distinct()

    return render(request,
                  'arachniscanner/arachni_list_vuln.html',
                  {'arachni_all_vul': arachni_all_vul,
                   'scan_id': scan_id,
                   'arachni_all_vul_close': arachni_all_vul_close
                   })


def arachni_scan_list(request):
    """
    Arachni Scan List.
    :param request:
    :return:
    """
    all_arachni_scan = arachni_scan_db.objects.all()

    return render(request,
                  'arachniscanner/arachni_scan_list.html',
                  {'all_arachni_scan': all_arachni_scan})


def arachni_vuln_data(request):
    """
    Arachni Vulnerability Data.
    :param request:
    :return:
    """
    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']
    else:
        vuln_id = None
    vuln_data = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request,
                  'arachniscanner/arachni_vuln_data.html',
                  {'vuln_data': vuln_data, })


def arachni_vuln_out(request):
    """
    Arachni Vulnerability details.
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
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        arachni_scan_result_db.objects.filter(vuln_id=vuln_id,
                                              scan_id=scan_id).update(false_positive=false_positive, vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = arachni_scan_result_db.objects.filter(scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                url = vi.url
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(dup_data).hexdigest()
                arachni_scan_result_db.objects.filter(vuln_id=vuln_id,
                                                      scan_id=scan_id).update(false_positive=false_positive,
                                                                              vuln_status=status,
                                                                              false_positive_hash=false_positive_hash
                                                                              )

        messages.add_message(request,
                             messages.SUCCESS,
                             'Vulnerability Status Changed')
        return HttpResponseRedirect(
            '/arachniscanner/arachni_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id, vuln_name))

    vuln_data = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                      name=name,
                                                      false_positive='No',
                                                      vuln_status='Open'
                                                      )

    vuln_data_close = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                            name=name,
                                                            false_positive='No',
                                                            vuln_status='Closed'
                                                            )

    false_data = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                       name=name,
                                                       false_positive='Yes')

    return render(request,
                  'arachniscanner/arachni_vuln_out.html',
                  {'vuln_data': vuln_data,
                   'false_data': false_data,
                   'jira_url': jira_url,
                   'vuln_data_close': vuln_data_close
                   })


def del_arachni_scan(request):
    """
    Delete Arachni Scans.
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
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = arachni_scan_db.objects.filter(scan_id=scan_id
                                                  )
            item.delete()
            item_results = arachni_scan_result_db.objects.filter(scan_id=scan_id)
            item_results.delete()
        messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/arachniscanner/arachni_scan_list/')


def edit_arachni_vuln(request):
    """
    The funtion Editing Arachni Vulnerability.
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
        vulnerabilityClassifications = request.POST.get("reference", )
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

        burp_scan_result_db.objects.filter(vuln_id=vuln_id).update(
            name=name,
            severity_color=vul_col,
            severity=severity,
            host=host,
            path=path,
            location=location,
            issueDetail=issuedetail,
            issueBackground=description,
            remediationBackground=solution,
            vulnerabilityClassifications=vulnerabilityClassifications,
        )

        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/arachniscanner/arachni_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'arachniscanner/edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def arachni_del_vuln(request):
    """
    The function Delete the Arachni Vulnerability.
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
            delete_vuln = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        arachni_all_vul = arachni_scan_result_db.objects.filter(scan_id=un_scanid).values(
            'name',
            'severity',
            'vuln_color'
        ).distinct()
        total_vul = len(arachni_all_vul)
        total_high = len(arachni_all_vul.filter(severity="high"))
        total_medium = len(arachni_all_vul.filter(severity="medium"))
        total_low = len(arachni_all_vul.filter(severity="low"))
        arachni_scan_db.objects.filter(scan_id=un_scanid).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low
        )
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/arachniscanner/arachni_list_vuln?scan_id=%s" % un_scanid)


def arachni_settings(request):
    """
    The function calling arachni Scanner setting page.
    :param request:
    :return:
    """
    arachni_hosts = None
    arachni_ports = None

    all_arachni = arachni_settings_db.objects.all()
    for arachni in all_arachni:
        # global arachni_api_key, arachni_hosts, arachni_ports
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port

    return render(request,
                  'arachniscanner/arachni_settings_form.html',
                  {
                      'arachni_host': arachni_hosts,
                      'arachni_port': arachni_ports,
                  }
                  )


def arachni_setting_update(request):
    """
    The function Update the arachni settings.
    :param request:
    :return:
    """

    if request.method == 'POST':
        arachnihost = request.POST.get("arachnihost", )
        port = request.POST.get("arachniport", )
        save_data = arachni_settings_db(
            arachni_url=arachnihost,
            arachni_port=port,
        )
        save_data.save()

        return HttpResponseRedirect('/webscanners/setting/')

    messages.add_message(request,
                         messages.SUCCESS,
                         'arachni Setting Updated ')

    return render(request,
                  'arachniscanner/arachni_settings_form.html')
