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

from django.shortcuts import render, HttpResponse, HttpResponseRedirect
from networkscanners.models import nessus_scan_results_db, nessus_scan_db, nessus_targets_db
import hashlib
from networkscanners.resources import NessusResource
from django.urls import reverse
from jiraticketing.models import jirasetting

Target = ''


def nessus_list(request):
    """
    nessus Scan list.
    :param request:
    :return:
    """
    username = request.user.username
    all_nessus_scan = nessus_scan_db.objects.filter(username=username).values(
        'report_name',
        'total_vuln',
        'total_high',
        'total_medium',
        'total_low',
        'total_dup',
        'scan_id',
        'scan_status',
        'date_time'
    ).distinct()

    return render(request, 'nessus/nessusscans_list.html',
                  {'all_nessus_scan': all_nessus_scan})


def nessus_target_list(request):
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    nessus_all_vuln = nessus_targets_db.objects.filter(scan_id=scan_id, username=username)

    return render(request, 'nessus/nessusscan_list_vuln.html',
                  {'nessus_all_vuln': nessus_all_vuln}
                  )


def nessus_target_data(request):
    username = request.user.username

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        target = request.GET['target']
    else:
        scan_id = None
        target = None

    nessus_vuln_data = nessus_scan_results_db.objects.filter(username=username, target=target, scan_id=scan_id)

    return render(request, 'nessus/nessusscan_vuln_data.html',
                  {'nessus_vuln_data': nessus_vuln_data})


def nessus_vuln_data(request):
    """
    :param request:
    :return:
    """
    global Target
    username = request.user.username
    jira_url = ''
    jira = jirasetting.objects.filter(username=username)
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        target = request.GET['target']
    else:
        scan_id = None
        target = None

    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        nessus_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                              scan_id=scan_id).update(false_positive=false_positive,
                                                                      vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                Name = vi.plugin_name
                Severity = vi.risk_factor
                Target = vi.target
                dup_data = Name + Severity + Target
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                nessus_scan_results_db.objects.filter(username=username, vuln_id=vuln_id,
                                                      scan_id=scan_id).update(false_positive=false_positive,
                                                                              vuln_status='Close',
                                                                              false_positive_hash=false_positive_hash
                                                                              )

        target_filter = nessus_scan_results_db.objects.filter(username=username,
                                                              scan_id=scan_id,
                                                              false_positive='No',
                                                              vuln_status='Open',
                                                              target=Target)

        target_total_vuln = len(target_filter)
        target_total_high = len(target_filter.filter(risk_factor="High"))
        target_total_medium = len(target_filter.filter(risk_factor="Medium"))
        target_total_low = len(target_filter.filter(risk_factor="Low"))
        target_total_duplicate = len(target_filter.filter(vuln_duplicate='Yes'))

        nessus_targets_db.objects.filter(username=username, scan_id=scan_id, target=Target).update(
            total_vuln=target_total_vuln,
            total_high=target_total_high,
            total_medium=target_total_medium,
            total_low=target_total_low,
            total_dup=target_total_duplicate,
        )

        ov_all_vul = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                           vuln_status='Open')
        total_vuln = len(ov_all_vul)
        total_high = len(ov_all_vul.filter(risk_factor="High"))
        total_medium = len(ov_all_vul.filter(risk_factor="Medium"))
        total_low = len(ov_all_vul.filter(risk_factor="Low"))
        total_duplicate = len(ov_all_vul.filter(vuln_duplicate='Yes'))

        nessus_scan_db.objects.filter(username=username, scan_id=scan_id) \
            .update(total_vuln=total_vuln,
                    total_high=total_high,
                    total_medium=total_medium,
                    total_low=total_low,
                    total_dup=total_duplicate,
                    )

        return HttpResponseRedirect(
            reverse('nessus:nessus_vuln_data') + '?scan_id=%s&target=%s' % (scan_id, Target))

    nessus_vuln_data = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             target=target,
                                                             vuln_status='Open',
                                                             false_positive='No'
                                                             )

    vuln_data_closed = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                             target=target,
                                                             vuln_status='Closed',
                                                             false_positive='No')
    false_data = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                       target=target,
                                                       false_positive='Yes')

    return render(request, 'nessus/nessusscan_vuln_data.html',
                  {'nessus_vuln_data': nessus_vuln_data,
                   'false_data': false_data,
                   'vuln_data_closed': vuln_data_closed,
                   'jira_url': jira_url
                   })


def nessus_details(request):
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

    nessus_vuln_details = nessus_scan_results_db.objects.filter(username=username,
                                                                scan_id=scan_id,
                                                                vuln_id=vuln_id
                                                                )

    return render(request, 'nessus/nessus_vuln_details.html',
                  {'nessus_vuln_details': nessus_vuln_details}
                  )


def del_nessus(request):
    """
    Delete nessus Scans.
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
            item = nessus_scan_db.objects.filter(username=username, scan_id=scan_id)
            item.delete()
            item_results = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id)
            item_results.delete()
            report_result = nessus_targets_db.objects.filter(username=username, scan_id=scan_id)
            report_result.delete()
        return HttpResponseRedirect(reverse('nessus:nessus_list'))


def nessus_del_vuln(request):
    """
    The function Delete the nessus Vulnerability.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        scan_id = request.POST.get("scan_id", )
        target = request.POST.get('target')
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = nessus_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        all_nessus_data = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id)

        total_vul = len(all_nessus_data)
        total_high = len(all_nessus_data.filter(risk_factor="High"))
        total_medium = len(all_nessus_data.filter(risk_factor="Medium"))
        total_low = len(all_nessus_data.filter(risk_factor="Low"))

        nessus_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,

        )

        all_nessus_target = nessus_scan_results_db.objects.filter(username=username, target=target)
        all_target_total_vuln = len(all_nessus_target)
        all_target_total_high = len(all_nessus_target.filter(risk_factor="High"))
        all_target_total_medium = len(all_nessus_target.filter(risk_factor="Medium"))
        all_target_total_low = len(all_nessus_target.filter(risk_factor="Low"))

        nessus_targets_db.objects.filter(username=username, scan_id=scan_id, target=target).update(
            total_vuln=all_target_total_vuln,
            total_high=all_target_total_high,
            total_medium=all_target_total_medium,
            total_low=all_target_total_low,
        )

        return HttpResponseRedirect(reverse('nessus:nessus_target_list') + '?scan_id=%s' % scan_id)


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        nessus_resource = NessusResource()
        queryset = nessus_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = nessus_resource.export(queryset)
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
