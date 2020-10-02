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
from staticscanners.models import retirejs_scan_results_db, retirejs_scan_db
import hashlib
from django.urls import reverse


def retirejsscans_list(request):
    """
    retirejs Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_retirejs_scan = retirejs_scan_db.objects.filter(username=username)

    return render(request, 'retirejsscanner/retirejsscans_list.html',
                  {'all_retirejs_scan': all_retirejs_scan})


def retirejsscan_list_vuln(request):
    """
    Vulnerability list.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    retirejs_all_vuln = retirejs_scan_results_db.objects.filter(username=username,
                                                                scan_id=scan_id).values(
        'test_name',
        'issue_severity',
        'scan_id',
        'vul_col',
    ).distinct()

    return render(request, 'retirejsscanner/retirejsscan_list_vuln.html',
                  {'retirejs_all_vuln': retirejs_all_vuln})


def retirejsscan_vuln_data(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
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
        retirejs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                scan_id=scan_id).update(false_positive=false_positive,
                                                                        vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.test_name
                filename = vi.filename
                Severity = vi.issue_severity
                dup_data = name + filename + Severity
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                retirejs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                        scan_id=scan_id).update(false_positive=false_positive,
                                                                                vuln_status='Close',
                                                                                false_positive_hash=false_positive_hash
                                                                                )

        all_retirejs_data = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                    false_positive='No',
                                                                    vuln_status='Open')

        total_vul = len(all_retirejs_data)
        total_high = len(all_retirejs_data.filter(severity='High'))
        total_medium = len(all_retirejs_data.filter(severity='Medium'))
        total_low = len(all_retirejs_data.filter(severity='Low'))
        total_duplicate = len(all_retirejs_data.filter(vuln_duplicate='Yes'))

        retirejs_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )

        return HttpResponseRedirect(
            reverse('/retirejsscanner/retirejsscan_vuln_data/') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))

    retirejs_vuln_data = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                 test_name=test_name,
                                                                 vuln_status='Open',
                                                                 false_positive='No')
    vuln_data_closed = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                               test_name=test_name,
                                                               vuln_status='Closed',
                                                               false_positive='No')
    false_data = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                         test_name=test_name,
                                                         false_positive='Yes')

    return render(request, 'retirejsscanner/retirejsscan_vuln_data.html',
                  {'retirejs_vuln_data': retirejs_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed
                   })


def retirejsscan_details(request):
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

    retirejs_vuln_details = retirejs_scan_results_db.objects.filter(username=username,
                                                                    scan_id=scan_id,
                                                                    vuln_id=vuln_id
                                                                    )

    return render(request, 'retirejsscanner/retirejs_vuln_details.html',
                  {'retirejs_vuln_details': retirejs_vuln_details}
                  )


def del_retirejs_scan(request):
    """
    Delete retirejs Scans.
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
            item = retirejs_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = retirejs_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('retirejsscanner:retirejsscans_list'))


def retirejs_del_vuln(request):
    """
    The function Delete the retirejs Vulnerability.
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
            delete_vuln = retirejs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_retirejs_data = retirejs_scan_results_db.objects.filter(username=username, scan_id=un_scanid)

        total_vul = len(all_retirejs_data)
        total_high = len(all_retirejs_data.filter(issue_severity="HIGH"))
        total_medium = len(all_retirejs_data.filter(issue_severity="MEDIUM"))
        total_low = len(all_retirejs_data.filter(issue_severity="LOW"))

        retirejs_scan_db.objects.filter(username=username, scan_id=un_scanid).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('retirejsscanner:retirejsscan_list_vuln') + '?scan_id=%s' % un_scanid)
