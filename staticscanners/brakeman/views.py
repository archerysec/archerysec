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
from staticscanners.models import brakeman_scan_results_db, brakeman_scan_db
import hashlib
from staticscanners.resources import brakemanResource
from django.urls import reverse
from jiraticketing.models import jirasetting
 
 
def brakeman_list(request):
    """
    brakeman Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_brakeman_scan = brakeman_scan_db.objects.filter(username=username)
 
    return render(request, 'brakeman/brakeman_list.html',
                  {'all_brakeman_scan': all_brakeman_scan})
 
 
def list_vuln(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None
 
    brakeman_all_vuln = brakeman_scan_results_db.objects.filter(scan_id=scan_id, username=username).values('name', 'vul_col', 'scan_id', 'severity', 'vuln_status').distinct()
 
    return render(request, 'brakeman/brakeman_list_vuln.html',
                  {'brakeman_all_vuln': brakeman_all_vuln}
                  )
 
 
def brakeman_vuln_data(request):
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
        test_name = request.GET['test_name']
    else:
        scan_id = None
        test_name = None
 
    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        brakeman_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                  scan_id=scan_id).update(false_positive=false_positive,
                                                                          vuln_status=status)
 
        if false_positive == 'Yes':
            vuln_info = brakeman_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                Name = vi.name
                severity = vi.severity
                dup_data = severity + Name
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                brakeman_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                          scan_id=scan_id).update(false_positive=false_positive,
                                                                                  vuln_status='Closed',
                                                                                  false_positive_hash=false_positive_hash
                                                                                  )
 
        all_brakeman_data = brakeman_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                        false_positive='No', vuln_status='Open')
 
        total_vul = len(all_brakeman_data)
        total_high = len(all_brakeman_data.filter(severity='High'))
        total_medium = len(all_brakeman_data.filter(severity='Medium'))
        total_low = len(all_brakeman_data.filter(severity='Low'))
        total_duplicate = len(all_brakeman_data.filter(vuln_duplicate='Yes'))
 
        brakeman_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
 
        )
 
        return HttpResponseRedirect(
            reverse('brakeman:brakeman_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))
 
    brakeman_vuln_data = brakeman_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                     name=test_name)
 
    return render(request, 'brakeman/brakeman_vuln_data.html',
                  {'brakeman_vuln_data': brakeman_vuln_data,
 
                   'jira_url': jira_url
                   })
 
 
def brakeman_details(request):
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
 
    brakeman_vuln_details = brakeman_scan_results_db.objects.filter(username=username,
                                                                        scan_id=scan_id,
                                                                        vuln_id=vuln_id
                                                                        )
 
    return render(request, 'brakeman/brakeman_vuln_details.html',
                  {'brakeman_vuln_details': brakeman_vuln_details}
                  )
 
 
def del_brakeman(request):
    """
    Delete brakeman Scans.
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
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = brakeman_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = brakeman_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('brakeman:brakeman_list'))
 
 
def brakeman_del_vuln(request):
    """
    The function Delete the brakeman Vulnerability.
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
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = brakeman_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_brakeman_data = brakeman_scan_results_db.objects.filter(username=username, scan_id=scan_id)
 
        total_vul = len(all_brakeman_data)
        total_high = len(all_brakeman_data.filter(severity="High"))
        total_medium = len(all_brakeman_data.filter(severity="Medium"))
        total_low = len(all_brakeman_data.filter(severity="Low"))
        total_duplicate = len(all_brakeman_data.filter(vuln_duplicate='Yes'))
 
        brakeman_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
 
        )
 
        return HttpResponseRedirect(reverse('brakeman:brakeman_all_vuln') + '?scan_id=%s' % scan_id)
 
 
def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")
 
        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
 
        brakeman_resource = brakemanResource()
        queryset = brakeman_scan_results_db.objects.filter(username=username, scan_id__in=value_split)
        dataset = brakeman_resource.export(queryset)
        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % 'brakeman_results'
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % 'brakeman_results'
            return response
        if report_type == 'yaml':
            response = HttpResponse(dataset.yaml, content_type='application/x-yaml')
            response['Content-Disposition'] = 'attachment; filename="%s.yaml"' % 'brakeman_results'
            return response