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
from compliance.models import dockle_scan_db, dockle_scan_results_db
import hashlib
from staticscanners.resources import dockleResource
from django.urls import reverse


def dockle_list(request):
    """
    dockle Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_dockle_scan = dockle_scan_db.objects.filter(username=username)

    return render(request, 'dockle/docklescans_list.html',
                  {'all_dockle_scan': all_dockle_scan})


def list_vuln(request):
    all_failed = ''
    all_passed = ''
    all_skipped = ''
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    dockle_all_vuln = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id)
    dockle_all_audit = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id)

    all_compliance = dockle_scan_db.objects.filter(username=username, scan_id=scan_id)

    return render(request, 'dockle/docklescan_list_vuln.html',
                  {'dockle_all_vuln': dockle_all_vuln,
                   'dockle_all_audit': dockle_all_audit,
                   'all_compliance': all_compliance

                   }
                  )


def dockle_vuln_data(request):
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

    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        dockle_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                              scan_id=scan_id).update(false_positive=false_positive,
                                                                      vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                Name = vi.Name
                NamespaceName = vi.NamespaceName
                Severity = vi.Severity
                dup_data = Name + Severity + NamespaceName
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                dockle_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                      scan_id=scan_id).update(false_positive=false_positive,
                                                                              vuln_status=status,
                                                                              false_positive_hash=false_positive_hash
                                                                              )

        return HttpResponseRedirect(
            reverse('dockle:dockle_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, vuln_id))

    dockle_vuln_data = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             vuln_id=vuln_id,
                                                             vuln_status='Open',
                                                             false_positive='No'
                                                             )

    vuln_data_closed = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             vuln_id=vuln_id,
                                                             vuln_status='Closed',
                                                             false_positive='No')
    false_data = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                       vuln_id=vuln_id,
                                                       false_positive='Yes')

    return render(request, 'dockle/docklescan_vuln_data.html',
                  {'dockle_vuln_data': dockle_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed
                   })


def dockle_details(request):
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

    dockle_vuln_details = dockle_scan_results_db.objects.filter(username=username,
                                                                scan_id=scan_id,
                                                                vuln_id=vuln_id
                                                                )

    return render(request, 'dockle/dockle_vuln_details.html',
                  {'dockle_vuln_details': dockle_vuln_details,
                   }
                  )


def del_dockle(request):
    """
    Delete dockle Scans.
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
            item = dockle_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse('dockle:dockle_list'))


def dockle_del_vuln(request):
    """
    The function Delete the dockle Vulnerability.
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
            delete_vuln = dockle_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_dockle_data = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vul = len(all_dockle_data)
        total_high = len(all_dockle_data.filter(Severity="High"))
        total_medium = len(all_dockle_data.filter(Severity="Medium"))
        total_low = len(all_dockle_data.filter(Severity="Low"))
        total_duplicate = len(all_dockle_data.filter(vuln_duplicate='Yes'))

        dockle_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )

        return HttpResponseRedirect(reverse('dockle:dockle_all_vuln' + '?scan_id=%s' % scan_id))


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        dockle_resource = dockleResource()
        queryset = dockle_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = dockle_resource.export(queryset)
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
