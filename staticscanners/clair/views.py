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
from staticscanners.models import clair_scan_results_db, clair_scan_db
import hashlib
from staticscanners.resources import ClairResource
from django.urls import reverse
from jiraticketing.models import jirasetting


def clair_list(request):
    """
    clair Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_clair_scan = clair_scan_db.objects.filter(username=username)

    return render(request, 'clair/clairscans_list.html',
                  {'all_clair_scan': all_clair_scan})


def list_vuln(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    clair_all_vuln = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id).exclude(vuln_status='Duplicate')

    return render(request, 'clair/clairscan_list_vuln.html',
                  {'clair_all_vuln': clair_all_vuln}
                  )


def clair_vuln_data(request):
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
        clair_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                             scan_id=scan_id).update(false_positive=false_positive,
                                                                     vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                Name = vi.Name
                NamespaceName = vi.NamespaceName
                Severity = vi.Severity
                dup_data = Name + Severity + NamespaceName
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                clair_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                     scan_id=scan_id).update(false_positive=false_positive,
                                                                             vuln_status='Close',
                                                                             false_positive_hash=false_positive_hash
                                                                             )

        all_clair_data = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                              vuln_status='Open')

        total_vul = len(all_clair_data)
        total_high = len(all_clair_data.filter(Severity='High'))
        total_medium = len(all_clair_data.filter(Severity='Medium'))
        total_low = len(all_clair_data.filter(Severity='Low'))
        total_duplicate = len(all_clair_data.filter(vuln_duplicate='Yes'))

        clair_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(
            reverse('clair:clair_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))

    clair_vuln_data = clair_scan_results_db.objects.filter(username=username,
                                                           scan_id=scan_id,
                                                           Name=test_name,
                                                           vuln_status='Open',
                                                           false_positive='No'
                                                           )

    vuln_data_closed = clair_scan_results_db.objects.filter(username=username,
                                                            scan_id=scan_id,
                                                            Name=test_name,
                                                            vuln_status='Closed',
                                                            false_positive='No')
    false_data = clair_scan_results_db.objects.filter(username=username,
                                                      scan_id=scan_id,
                                                      Name=test_name,
                                                      false_positive='Yes')

    return render(request, 'clair/clairscan_vuln_data.html',
                  {'clair_vuln_data': clair_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed,
                   'jira_url': jira_url
                   })


def clair_details(request):
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

    clair_vuln_details = clair_scan_results_db.objects.filter(username=username,
                                                              scan_id=scan_id,
                                                              vuln_id=vuln_id
                                                              )

    return render(request, 'clair/clair_vuln_details.html',
                  {'clair_vuln_details': clair_vuln_details}
                  )


def del_clair(request):
    """
    Delete clair Scans.
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
            item = clair_scan_db.objects.filter(scan_id=scan_id, username=username)
            item.delete()
            item_results = clair_scan_results_db.objects.filter(scan_id=scan_id, username=username)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('clair:clair_list'))


def clair_del_vuln(request):
    """
    The function Delete the clair Vulnerability.
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
            delete_vuln = clair_scan_results_db.objects.filter(vuln_id=vuln_id, username=username)
            delete_vuln.delete()
        all_clair_data = clair_scan_results_db.objects.filter(scan_id=scan_id, username=username)

        total_vul = len(all_clair_data)
        total_high = len(all_clair_data.filter(Severity="High"))
        total_medium = len(all_clair_data.filter(Severity="Medium"))
        total_low = len(all_clair_data.filter(Severity="Low"))
        total_duplicate = len(all_clair_data.filter(vuln_duplicate='Yes'))

        clair_scan_db.objects.filter(scan_id=scan_id, username=username).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('clair:clair_all_vuln') + '?scan_id=%s' % scan_id)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        clair_resource = ClairResource()
        queryset = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = clair_resource.export(queryset)
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
