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
from staticscanners.models import bandit_scan_results_db, bandit_scan_db
import hashlib
from django.urls import reverse
from jiraticketing.models import jirasetting


def banditscans_list(request):
    """
    Bandit Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_bandit_scan = bandit_scan_db.objects.filter(username=username)

    return render(request, 'banditscanner/banditscans_list.html',
                  {'all_bandit_scan': all_bandit_scan})


def banditscan_list_vuln(request):
    """
    Vulnerability list.
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
    else:
        scan_id = None

    bandit_all_vuln = bandit_scan_results_db.objects.filter(username=username,
                                                            scan_id=scan_id).values(
        'test_name',
        'issue_severity',
        'scan_id',
        'vuln_status',
        'vul_col',
    ).distinct().exclude(vuln_status='Duplicate')

    return render(request, 'banditscanner/banditscan_list_vuln.html',
                  {'bandit_all_vuln': bandit_all_vuln,
                   'jira_url': jira_url
                   })


def banditscan_vuln_data(request):
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
        bandit_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                              scan_id=scan_id).update(false_positive=false_positive,
                                                                      vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.test_name
                filename = vi.filename
                Severity = vi.issue_severity
                dup_data = name + filename + Severity
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                bandit_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                      scan_id=scan_id).update(false_positive=false_positive,
                                                                              vuln_status='Close',
                                                                              false_positive_hash=false_positive_hash
                                                                              )

        all_bandit_data = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                                vuln_status='Open')

        total_vul = len(all_bandit_data)
        total_high = len(all_bandit_data.filter(issue_severity="HIGH"))
        total_medium = len(all_bandit_data.filter(issue_severity="MEDIUM"))
        total_low = len(all_bandit_data.filter(issue_severity="LOW"))
        total_duplicate = len(all_bandit_data.filter(vuln_duplicate='Yes'))

        bandit_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(
            reverse('banditscanner:banditscan_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))

    bandit_vuln_data = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             test_name=test_name,
                                                             vuln_status='Open',
                                                             false_positive='No')
    vuln_data_closed = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             test_name=test_name,
                                                             vuln_status='Closed',
                                                             false_positive='No')
    false_data = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                       test_name=test_name,
                                                       false_positive='Yes')

    return render(request, 'banditscanner/banditscan_vuln_data.html',
                  {'bandit_vuln_data': bandit_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed,
                   'jira_url': jira_url
                   })


def banditscan_details(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    jira_url = ''
    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        vuln_id = request.GET['vuln_id']
    else:
        scan_id = None
        vuln_id = None

    bandit_vuln_details = bandit_scan_results_db.objects.filter(username=username,
                                                                scan_id=scan_id,
                                                                vuln_id=vuln_id
                                                                )

    return render(request, 'banditscanner/bandit_vuln_details.html',
                  {'bandit_vuln_details': bandit_vuln_details}
                  )


def del_bandit_scan(request):
    """
    Delete Bandit Scans.
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
            item = bandit_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse('banditscanner:banditscans_list'))


def bandit_del_vuln(request):
    """
    The function Delete the bandit Vulnerability.
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
            delete_vuln = bandit_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_bandit_data = bandit_scan_results_db.objects.filter(username=username, scan_id=un_scanid)

        total_vul = len(all_bandit_data)
        total_high = len(all_bandit_data.filter(issue_severity="HIGH"))
        total_medium = len(all_bandit_data.filter(issue_severity="MEDIUM"))
        total_low = len(all_bandit_data.filter(issue_severity="LOW"))

        bandit_scan_db.objects.filter(username=username, scan_id=un_scanid).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('banditscanner:banditscan_list_vuln/') + '?scan_id=%s' % un_scanid)
