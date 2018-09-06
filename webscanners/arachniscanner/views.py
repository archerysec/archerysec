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
from django.http import HttpResponseRedirect
from django.shortcuts import render
from webscanners.models import burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db
from jiraticketing.models import jirasetting
import hashlib


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
                false_positive_hash = hashlib.sha1(dup_data).hexdigest()
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
