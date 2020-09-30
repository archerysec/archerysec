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

from django.shortcuts import render,  HttpResponse, HttpResponseRedirect
from staticscanners.models import checkmarx_scan_results_db, checkmarx_scan_db
import hashlib
from staticscanners.resources import checkmarxResource
from django.urls import reverse
from jiraticketing.models import jirasetting


def checkmarx_list(request):
    """
    checkmarx Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_checkmarx_scan = checkmarx_scan_db.objects.filter(username=username)

    return render(request, 'checkmarx/checkmarx_list.html',
                  {'all_checkmarx_scan': all_checkmarx_scan})


def list_vuln(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    checkmarx_all_vuln = checkmarx_scan_results_db.objects.filter(username=username,
                                                                  scan_id=scan_id, vuln_status='Open').values(
        'name',
        'severity',
        'vul_col',
        'scan_id').distinct().exclude(vuln_status='Duplicate')

    return render(request, 'checkmarx/checkmarx_list_vuln.html',
                  {'checkmarx_all_vuln': checkmarx_all_vuln}
                  )


def checkmarx_vuln_data(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    jira_url = ''
    jira = jirasetting.objects.filter(username=username)
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        name = request.GET['name']
    else:
        scan_id = None
        name = None

    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        checkmarx_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                 scan_id=scan_id).update(false_positive=false_positive,
                                                                         vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                severity = vi.severity
                file_name = vi.file_name
                dup_data = str(name) + str(severity) + str(file_name)
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                checkmarx_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                         scan_id=scan_id).update(false_positive=false_positive,
                                                                                 vuln_status='Close',
                                                                                 false_positive_hash=false_positive_hash)

        all_checkmarx_data = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                      false_positive='No', vuln_status='Open')

        total_vul = len(all_checkmarx_data)
        total_high = len(all_checkmarx_data.filter(severity='High'))
        total_medium = len(all_checkmarx_data.filter(severity='Medium'))
        total_low = len(all_checkmarx_data.filter(severity='Low'))
        total_duplicate = len(all_checkmarx_data.filter(vuln_duplicate='Yes'))

        checkmarx_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(
            reverse('checkmarx:checkmarx_vuln_data') + '?scan_id=%s&name=%s' % (scan_id, vuln_name))

    checkmarx_vuln_data = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                   name=name,
                                                                   vuln_status='Open',
                                                                   false_positive='No'
                                                                   )

    vuln_data_closed = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                name=name,
                                                                vuln_status='Closed',
                                                                false_positive='No')
    false_data = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                          name=name,
                                                          false_positive='Yes')

    return render(request, 'checkmarx/checkmarx_vuln_data.html',
                  {'checkmarx_vuln_data': checkmarx_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed,
                   'jira_url': jira_url
                   })


def checkmarx_details(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        vuln_id = request.GET['vuln_id']
    else:
        scan_id = None
        vuln_id = None

    checkmarx_vuln_details = checkmarx_scan_results_db.objects.filter(username=username,
                                                                      scan_id=scan_id,
                                                                      vuln_id=vuln_id
                                                                      )

    return render(request, 'checkmarx/checkmarx_vuln_details.html',
                  {'checkmarx_vuln_details': checkmarx_vuln_details}
                  )


def del_checkmarx(request):
    """
    Delete checkmarx Scans.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = checkmarx_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('checkmarx:checkmarx_list'))


def checkmarx_del_vuln(request):
    """
    The function Delete the checkmarx Vulnerability.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        scan_id = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = checkmarx_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_checkmarx_data = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vul = len(all_checkmarx_data)
        total_high = len(all_checkmarx_data.filter(severity="High"))
        total_medium = len(all_checkmarx_data.filter(severity="Medium"))
        total_low = len(all_checkmarx_data.filter(severity="Low"))
        total_duplicate = len(all_checkmarx_data.filter(vuln_duplicate='Yes'))

        checkmarx_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('checkmarx:checkmarx_all_vuln') + '?scan_id=%s' % scan_id)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        checkmarx_resource = checkmarxResource()
        queryset = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = checkmarx_resource.export(queryset)
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
