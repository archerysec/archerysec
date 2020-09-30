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
from staticscanners.models import findbugs_scan_results_db, findbugs_scan_db
import hashlib
from staticscanners.resources import FindbugResource
from django.urls import reverse


def findbugs_list(request):
    """
    findbugs Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_findbugs_scan = findbugs_scan_db.objects.filter(username=username)

    return render(request, 'findbugs/findbugsscans_list.html',
                  {'all_findbugs_scan': all_findbugs_scan})


def list_vuln(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    findbugs_all_vuln = findbugs_scan_results_db.objects.filter(scan_id=scan_id, username=username).exclude(vuln_status='Duplicate')

    return render(request, 'findbugs/findbugsscan_list_vuln.html',
                  {'findbugs_all_vuln': findbugs_all_vuln}
                  )


def findbugs_vuln_data(request):
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
        findbugs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                scan_id=scan_id).update(false_positive=false_positive,
                                                                        vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                classname = vi.classname
                risk = vi.risk
                dup_data = name + classname + risk
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                findbugs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                        scan_id=scan_id).update(false_positive=false_positive,
                                                                                vuln_status='Close',
                                                                                false_positive_hash=false_positive_hash
                                                                                )

        all_findbugs_data = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                    false_positive='No',
                                                                    vuln_status='Open')

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(priority="1"))
        total_medium = len(all_findbugs_data.filter(priority="2"))
        total_low = len(all_findbugs_data.filter(priority="3"))
        total_duplicate = len(all_findbugs_data.filter(vuln_duplicate='Yes'))

        findbugs_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low

        )

        return HttpResponseRedirect(
            reverse('findbugs:findbugs_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))

    findbugs_vuln_data = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                 name=test_name,
                                                                 vuln_status='Open',
                                                                 false_positive='No'
                                                                 )

    vuln_data_closed = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                               name=test_name,
                                                               vuln_status='Closed',
                                                               false_positive='No')
    false_data = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                         name=test_name,
                                                         false_positive='Yes')

    return render(request, 'findbugs/findbugsscan_vuln_data.html',
                  {'findbugs_vuln_data': findbugs_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed
                   })


def findbugs_details(request):
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

    findbugs_vuln_details = findbugs_scan_results_db.objects.filter(username=username,
                                                                    scan_id=scan_id,
                                                                    vuln_id=vuln_id
                                                                    )

    return render(request, 'findbugs/findbugs_vuln_details.html',
                  {'findbugs_vuln_details': findbugs_vuln_details}
                  )


def del_findbugs(request):
    """
    Delete findbugs Scans.
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
            item = findbugs_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('findbugs:findbugs_list'))


def findbugs_del_vuln(request):
    """
    The function Delete the findbugs Vulnerability.
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
            delete_vuln = findbugs_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_findbugs_data = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(priority="1"))
        total_medium = len(all_findbugs_data.filter(priority="2"))
        total_low = len(all_findbugs_data.filter(priority="3"))
        total_duplicate = len(all_findbugs_data.filter(vuln_duplicate='Yes'))

        findbugs_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('findbugs:findbugs_all_vuln') + '?scan_id=%s' % scan_id)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        findbugs_resource = FindbugResource()
        queryset = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = findbugs_resource.export(queryset)
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
