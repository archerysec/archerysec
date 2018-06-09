# -*- coding: utf-8 -*-
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

""" Author: Anand Tiwari """

from __future__ import unicode_literals
import uuid
from manual_scan.models import manual_scan_results_db, manual_scans_db
from datetime import datetime

from django.shortcuts import render, HttpResponseRedirect


def list_scan(request):
    """

    :param request:
    :return:
    """
    all_scans = manual_scans_db.objects.all()

    return render(request,
                  'list_scan.html',
                  {'all_scans': all_scans}
                  )


def add_list_scan(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        date_time = datetime.now()
        scanid = uuid.uuid4()

        dump_scan = manual_scans_db(
            date_time=date_time,
            scan_url=scan_url,
            scan_id=scanid,
            # project_id=project_id,
        )
        dump_scan.save()
        return HttpResponseRedirect('/manual_scan/')

    return render(request, 'add_list_scan.html')


def vuln_list(request):
    """

    :param request:
    :return:
    """

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        all_vuln = manual_scan_results_db.objects.filter(scan_id=scan_id)

    return render(request,
                  'manual_vuln_list.html',
                  {'all_vuln': all_vuln,
                   'scan_id': scan_id
                   }
                  )


def add_vuln(request):
    """

    :param request:
    :return:
    """
    scanid = None
    severity_color = None

    if request.method == 'GET':
        scanid = request.GET['scan_id']

    if request.method == 'POST':
        vuln_name = request.POST.get('vuln_name')
        # project_id = request.POST.get('project_id')
        severity = request.POST.get('severity')
        vuln_url = request.POST.get('vuln_url')
        description = request.POST.get('description')
        solution = request.POST.get('solution')
        request_header = request.POST.get('request_header')
        response_header = request.POST.get('response_header')
        reference = request.POST.get('reference')
        scan_id = request.POST.get('scan_id')
        date_time = datetime.now()
        vuln_id = uuid.uuid4()

        if severity == "Critical":
            severity_color = "important"

        elif severity == "High":
            severity_color = 'important'

        elif severity == "Important":
            severity_color = "important"

        elif severity == 'Medium':
            severity_color = "warning"

        elif severity == 'Low':
            severity_color = "info"

        elif severity == 'informational':
            severity_color = "info"

        dump_data = manual_scan_results_db(
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            # project_id=project_id,
            severity_color=severity_color,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            request_header=request_header,
            response_header=response_header,
            reference=reference,
            scan_id=scan_id
        )
        dump_data.save()

        all_scan_data = manual_scan_results_db.objects.filter(scan_id=scan_id)

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        manual_scans_db.objects.filter(scan_id=scan_id).update(
            date_time=date_time,
            scan_url=vuln_url,
            # project_id=project_id,
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
        )

        return HttpResponseRedirect('/manual_scan/')

    return render(request,
                  'add_manual_vuln.html',
                  {'scanid': scanid})


def vuln_details(request):
    """

    :param request:
    :return:
    """

    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']

        vuln_detail = manual_scan_results_db.objects.filter(vuln_id=vuln_id)

    return render(request, 'manual_vuln_data.html', {'vuln_detail': vuln_detail})


def edit_vuln(request):
    """

    :param request:
    :return:
    """
    pass


def del_vuln(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        get_vuln_id = request.POST.get('vuln_id')

        scan_item = str(get_vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            del_vuln = manual_scan_results_db.objects.filter(vuln_id=vuln_id)
            del_vuln.delete()

        all_scan_data = manual_scan_results_db.objects.filter(scan_id=scan_id)

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        manual_scans_db.objects.filter(scan_id=scan_id).update(
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
        )

        return HttpResponseRedirect('/manual_scan/vuln_list/?scan_id=%s' % scan_id)


def del_scan(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        get_scan_id = request.POST.get('scan_id')

        scan_item = str(get_scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            del_scan = manual_scan_results_db.objects.filter(scan_id=scan_id)
            del_scan.delete()

            del_scan_info = manual_scans_db.objects.filter(scan_id=scan_id)
            del_scan_info.delete()

        return HttpResponseRedirect('/manual_scan/')
