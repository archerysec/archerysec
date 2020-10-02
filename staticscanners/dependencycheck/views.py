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
from staticscanners.models import dependencycheck_scan_results_db, dependencycheck_scan_db
import hashlib
from staticscanners.resources import DependencyResource
from django.urls import reverse


def dependencycheck_list(request):
    """
    dependencycheck Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_dependencycheck_scan = dependencycheck_scan_db.objects.filter(username=username)

    return render(request, 'dependencycheck/dependencycheckscans_list.html',
                  {'all_dependencycheck_scan': all_dependencycheck_scan})


def list_vuln(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    dependencycheck_all_vuln = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id).exclude(vuln_status='Duplicate')

    return render(request, 'dependencycheck/dependencycheckscan_list_vuln.html',
                  {'dependencycheck_all_vuln': dependencycheck_all_vuln}
                  )


def dependencycheck_vuln_data(request):
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
        dependencycheck_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                       scan_id=scan_id).update(false_positive=false_positive,
                                                                               vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                filename = vi.fileName
                Severity = vi.severity
                dup_data = name + filename + Severity
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                dependencycheck_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                               scan_id=scan_id).update(false_positive=false_positive,
                                                                                       vuln_status='Close',
                                                                                       false_positive_hash=false_positive_hash
                                                                                       )

        all_dependency_data = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                                             vuln_status='Open')

        total_vul = len(all_dependency_data)
        total_high = len(all_dependency_data.filter(severity="High"))
        total_medium = len(all_dependency_data.filter(severity="Medium"))
        total_low = len(all_dependency_data.filter(severity="Low"))
        total_duplicate = len(all_dependency_data.filter(vuln_duplicate='Yes'))

        dependencycheck_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(
            reverse('dependencycheck:dependencycheck_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_name))

    dependencycheck_vuln_data = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                               name=test_name,
                                                                               vuln_status='Open',
                                                                               false_positive='No'
                                                                               )

    vuln_data_closed = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                      name=test_name,
                                                                      vuln_status='Closed',
                                                                      false_positive='No')
    false_data = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                name=test_name,
                                                                false_positive='Yes')

    return render(request, 'dependencycheck/dependencycheckscan_vuln_data.html',
                  {'dependencycheck_vuln_data': dependencycheck_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed
                   })


def dependencycheck_details(request):
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

    dependencycheck_vuln_details = dependencycheck_scan_results_db.objects.filter(username=username,
        scan_id=scan_id,
        vuln_id=vuln_id
    )

    return render(request, 'dependencycheck/dependencycheck_vuln_details.html',
                  {'dependencycheck_vuln_details': dependencycheck_vuln_details}
                  )


def del_dependencycheck(request):
    """
    Delete dependencycheck Scans.
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
            item = dependencycheck_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse('dependencycheck:dependencycheck_list'))


def dependencycheck_del_vuln(request):
    """
    The function Delete the dependencycheck Vulnerability.
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
            delete_vuln = dependencycheck_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()

        all_dependency_data = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vul = len(all_dependency_data)
        total_high = len(all_dependency_data.filter(severity="High"))
        total_medium = len(all_dependency_data.filter(severity="Medium"))
        total_low = len(all_dependency_data.filter(severity="Low"))
        total_duplicate = len(all_dependency_data.filter(vuln_duplicate='Yes'))

        dependencycheck_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low
        )

        return HttpResponseRedirect(reverse('dependencycheck:dependencycheck_all_vuln') + '?scan_id=%s' % scan_id)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        dependency_resource = DependencyResource()
        queryset = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = dependency_resource.export(queryset)
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
