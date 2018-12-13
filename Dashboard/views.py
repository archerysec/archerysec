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

from webscanners.models import zap_scans_db, \
    burp_scan_db, \
    arachni_scan_db, \
    netsparker_scan_db, \
    webinspect_scan_db, \
    zap_scan_results_db, \
    burp_scan_result_db, \
    arachni_scan_result_db, \
    netsparker_scan_result_db, \
    webinspect_scan_result_db, \
    acunetix_scan_db
from networkscanners.models import scan_save_db, nessus_scan_db, ov_scan_result_db, nessus_report_db
from projects.models import project_db
from django.shortcuts import render, render_to_response, HttpResponse
from itertools import chain
from django.db.models import Sum
import datetime

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def vuln_static_dashboard(request):
    """
    Vulnerability Dashboard.
    :param request:
    :return:
    """
    global dash_year
    high_list = []
    all_project = project_db.objects.all()
    all_zap_scan = zap_scans_db.objects.aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.aggregate(Sum('total_vul'))
    all_arachni_scan = arachni_scan_db.objects.aggregate(Sum('total_vul'))
    all_netsparker_scan = netsparker_scan_db.objects.aggregate(Sum('total_vul'))
    all_webinspect_scan = webinspect_scan_db.objects.aggregate(Sum('total_vul'))
    all_acunetix_scan = acunetix_scan_db.objects.aggregate(Sum('total_vul'))

    all_openvas_scan = scan_save_db.objects.aggregate(Sum('total_vul'))
    all_nessus_scan = nessus_scan_db.objects.aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value

    for key, value in all_burp_scan.iteritems():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value

    for key, value in all_arachni_scan.iteritems():
        if value is None:
            all_arachni = '0'
        else:
            all_arachni = value

    for key, value in all_netsparker_scan.iteritems():
        if value is None:
            all_netsparker = '0'
        else:
            all_netsparker = value

    for key, value in all_webinspect_scan.iteritems():
        if value is None:
            all_webinspect = '0'
        else:
            all_webinspect = value

    for key, value in all_acunetix_scan.iteritems():
        if value is None:
            all_acunetix = '0'
        else:
            all_acunetix = value

    for key, value in all_openvas_scan.iteritems():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value
    for key, value in all_nessus_scan.iteritems():
        if value is None:
            all_nessus = '0'
        else:
            all_nessus = value

    all_vuln = int(all_zap) + \
        int(all_burp) + \
        int(all_openvas) + \
        int(all_nessus) + \
        int(all_arachni) + \
        int(all_netsparker) + \
        int(all_webinspect) + \
        int(all_acunetix)

    total_network = int(all_openvas) + int(all_nessus)

    total_web = int(all_zap) + \
        int(all_burp) + \
        int(all_arachni) + \
        int(all_netsparker) + \
        int(all_webinspect) + \
        int(all_acunetix)

    all_zap_high = zap_scans_db.objects.aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.aggregate(Sum('high_vul'))
    all_webinspect_high = webinspect_scan_db.objects.aggregate(Sum('high_vul'))
    all_arachni_high = arachni_scan_db.objects.aggregate(Sum('high_vul'))
    all_netsparker_high = netsparker_scan_db.objects.aggregate(Sum('high_vul'))
    all_acunetix_high = acunetix_scan_db.objects.aggregate(Sum('high_vul'))

    all_openvas_high = scan_save_db.objects.aggregate(Sum('high_total'))
    all_nessus_high = nessus_scan_db.objects.aggregate(Sum('high_total'))

    for key, value in all_zap_high.iteritems():
        if value is None:
            zap_high = '0'
        else:
            zap_high = value

    for key, value in all_burp_high.iteritems():
        if value is None:
            burp_high = '0'
        else:
            burp_high = value
    for key, value in all_webinspect_high.iteritems():
        if value is None:
            webinspect_high = '0'
        else:
            webinspect_high = value

    for key, value in all_arachni_high.iteritems():
        if value is None:
            arachni_high = '0'
        else:
            arachni_high = value

    for key, value in all_netsparker_high.iteritems():
        if value is None:
            netsparker_high = '0'
        else:
            netsparker_high = value

    for key, value in all_acunetix_high.iteritems():
        if value is None:
            acunetix_high = '0'
        else:
            acunetix_high = value

    for key, value in all_nessus_high.iteritems():
        if value is None:
            nessus_high = '0'
        else:
            nessus_high = value

    for key, value in all_openvas_high.iteritems():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    all_high = int(zap_high) + \
        int(burp_high) + \
        int(openvas_high) + \
        int(arachni_high) + \
        int(webinspect_high) + \
        int(netsparker_high) + \
        int(acunetix_high) + \
        int(nessus_high)

    all_web_high = int(zap_high) + \
        int(burp_high) + \
        int(arachni_high) + \
        int(webinspect_high) + \
        int(netsparker_high) + \
        int(acunetix_high)

    all_network_high = int(openvas_high) + int(nessus_high)

    all_zap_medium = zap_scans_db.objects.aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.aggregate(Sum('medium_vul'))
    all_arachni_medium = arachni_scan_db.objects.aggregate(Sum('medium_vul'))
    all_webinspect_medium = webinspect_scan_db.objects.aggregate(Sum('medium_vul'))
    all_netsparker_medium = netsparker_scan_db.objects.aggregate(Sum('medium_vul'))
    all_acunetix_medium = acunetix_scan_db.objects.aggregate(Sum('medium_vul'))

    all_openvas_medium = scan_save_db.objects.aggregate(Sum('medium_total'))
    all_nessus_medium = nessus_scan_db.objects.aggregate(Sum('medium_total'))

    for key, value in all_zap_medium.iteritems():
        if value is None:
            zap_medium = '0'
        else:
            zap_medium = value

    for key, value in all_burp_medium.iteritems():
        if value is None:
            burp_medium = '0'
        else:
            burp_medium = value

    for key, value in all_arachni_medium.iteritems():
        if value is None:
            arachni_medium = '0'
        else:
            arachni_medium = value

    for key, value in all_webinspect_medium.iteritems():
        if value is None:
            webinspect_medium = '0'
        else:
            webinspect_medium = value

    for key, value in all_netsparker_medium.iteritems():
        if value is None:
            netsparker_medium = '0'
        else:
            netsparker_medium = value

    for key, value in all_acunetix_medium.iteritems():
        if value is None:
            acunetix_medium = '0'
        else:
            acunetix_medium = value

    for key, value in all_openvas_medium.iteritems():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    for key, value in all_nessus_medium.iteritems():
        if value is None:
            nessus_medium = '0'
        else:
            nessus_medium = value

    all_medium = int(zap_medium) + \
        int(burp_medium) + \
        int(openvas_medium) + \
        int(arachni_medium) + \
        int(webinspect_medium) + \
        int(netsparker_medium) + \
        int(acunetix_medium) + int(nessus_medium)

    all_web_medium = int(zap_medium) + \
        int(burp_medium) + \
        int(arachni_medium) + \
        int(webinspect_medium) + \
        int(netsparker_medium) + \
        int(acunetix_medium)

    all_network_medium = int(openvas_medium) + int(nessus_medium)

    all_zap_low = zap_scans_db.objects.aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.aggregate(Sum('low_vul'))
    all_arachni_low = arachni_scan_db.objects.aggregate(Sum('low_vul'))
    all_webinspect_low = webinspect_scan_db.objects.aggregate(Sum('low_vul'))
    all_netsparker_low = netsparker_scan_db.objects.aggregate(Sum('low_vul'))
    all_acunetix_low = acunetix_scan_db.objects.aggregate(Sum('low_vul'))

    all_openvas_low = scan_save_db.objects.aggregate(Sum('low_total'))
    all_nessus_low = nessus_scan_db.objects.aggregate(Sum('low_total'))

    for key, value in all_zap_low.iteritems():
        if value is None:
            zap_low = '0'
        else:
            zap_low = value

    for key, value in all_burp_low.iteritems():
        if value is None:
            burp_low = '0'
        else:
            burp_low = value

    for key, value in all_arachni_low.iteritems():
        if value is None:
            arachni_low = '0'
        else:
            arachni_low = value

    for key, value in all_webinspect_low.iteritems():
        if value is None:
            webinspect_low = '0'
        else:
            webinspect_low = value

    for key, value in all_netsparker_low.iteritems():
        if value is None:
            netsparker_low = '0'
        else:
            netsparker_low = value

    for key, value in all_acunetix_low.iteritems():
        if value is None:
            acunetix_low = '0'
        else:
            acunetix_low = value

    for key, value in all_openvas_low.iteritems():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    for key, value in all_nessus_low.iteritems():
        if value is None:
            nessus_low = '0'
        else:
            nessus_low = value

    all_low = int(zap_low) + \
        int(burp_low) + \
        int(openvas_low) + \
        int(arachni_low) + \
        int(webinspect_low) + \
        int(netsparker_low) + \
        int(acunetix_low) + \
        int(nessus_low)

    all_web_low = int(zap_low) + \
        int(burp_low) + \
        int(arachni_low) + \
        int(webinspect_low) + \
        int(netsparker_low) + \
        int(acunetix_low)

    all_network_low = int(openvas_low) + int(nessus_low)

    dash_year = datetime.date.today().year

    try:
        if request.method == "POST":
            dash_year = request.POST.get("year")
        high_list = []
        for m in range(1, 13):
            high_zap = zap_scans_db.objects. \
                filter(date_time__year=dash_year,
                       date_time__month=m).aggregate(
                           Sum('high_vul'))
            high_burp = burp_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_vul'))

            high_arachni = arachni_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_vul'))

            high_webinspect = webinspect_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_vul'))

            high_netsparker = netsparker_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_vul'))

            high_acunetix_low = acunetix_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_vul'))

            high_nessus = nessus_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('high_total'))

            high_openvas = scan_save_db.objects. \
                filter(date_time__year=dash_year,
                       date_time__month=m).aggregate(
                           Sum('high_total'))

            for key, value in high_zap.iteritems():
                if value is None:
                    zap_high = '0'
                else:
                    zap_high = value
            for key, value in high_burp.iteritems():
                if value is None:
                    burp_high = '0'
                else:
                    burp_high = value

            for key, value in high_arachni.iteritems():
                if value is None:
                    arachni_high = '0'
                else:
                    arachni_high = value

            for key, value in high_webinspect.iteritems():
                if value is None:
                    webinspect_high = '0'
                else:
                    webinspect_high = value

            for key, value in high_netsparker.iteritems():
                if value is None:
                    netsparker_high = '0'
                else:
                    netsparker_high = value

            for key, value in high_acunetix_low.iteritems():
                if value is None:
                    acunetix_high = '0'
                else:
                    acunetix_high = value

            for key, value in high_nessus.iteritems():
                if value is None:
                    nessus_high = '0'
                else:
                    nessus_high = value

            for key, value in high_openvas.iteritems():
                if value is None:
                    openvas_high = '0'
                else:
                    openvas_high = value
            global data
            all_high_stat = int(zap_high) + \
                int(burp_high) + \
                int(openvas_high) + \
                int(arachni_high) + \
                int(webinspect_high) + \
                int(netsparker_high) + \
                int(acunetix_high) + \
                int(nessus_high)

            medium_zap = zap_scans_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))
            medium_burp = burp_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))
            # medium_openvas = scan_save_db. \
            #     objects.filter(date_time__year=dash_year,
            #                    date_time__month=m).aggregate(
            #     Sum('medium_total'))

            for key, value in medium_zap.iteritems():
                if value is None:
                    zap_medium = '0'
                else:
                    zap_medium = value
            for key, value in medium_burp.iteritems():
                if value is None:
                    burp_medium = '0'
                else:
                    burp_medium = value

            medium_arachni = arachni_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))

            medium_webinspect = webinspect_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))

            medium_netsparker = netsparker_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))

            medium_acunetix_low = acunetix_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_vul'))

            medium_nessus = nessus_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('medium_total'))

            medium_openvas = scan_save_db.objects. \
                filter(date_time__year=dash_year,
                       date_time__month=m).aggregate(
                           Sum('medium_total'))

            for key, value in medium_zap.iteritems():
                if value is None:
                    zap_medium = '0'
                else:
                    zap_medium = value
            for key, value in medium_burp.iteritems():
                if value is None:
                    burp_medium = '0'
                else:
                    burp_medium = value

            for key, value in medium_arachni.iteritems():
                if value is None:
                    arachni_medium = '0'
                else:
                    arachni_medium = value

            for key, value in medium_webinspect.iteritems():
                if value is None:
                    webinspect_medium = '0'
                else:
                    webinspect_medium = value

            for key, value in medium_netsparker.iteritems():
                if value is None:
                    netsparker_medium = '0'
                else:
                    netsparker_medium = value

            for key, value in medium_acunetix_low.iteritems():
                if value is None:
                    acunetix_medium = '0'
                else:
                    acunetix_medium = value

            for key, value in medium_nessus.iteritems():
                if value is None:
                    nessus_medium = '0'
                else:
                    nessus_medium = value

            for key, value in medium_openvas.iteritems():
                if value is None:
                    openvas_medium = '0'
                else:
                    openvas_medium = value
            global data
            all_medium_stat = int(zap_medium) + \
                int(burp_medium) + \
                int(openvas_medium) + \
                int(arachni_medium) + \
                int(webinspect_medium) + \
                int(netsparker_medium) + \
                int(acunetix_medium) + \
                int(nessus_medium)

            low_zap = zap_scans_db.objects. \
                filter(date_time__year=dash_year,
                       date_time__month=m).aggregate(
                           Sum('low_vul'))
            low_burp = burp_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_vul'))

            low_arachni = arachni_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_vul'))

            low_webinspect = webinspect_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_vul'))

            low_netsparker = netsparker_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_vul'))

            low_acunetix_low = acunetix_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_vul'))

            low_nessus = nessus_scan_db. \
                objects.filter(date_time__year=dash_year,
                               date_time__month=m).aggregate(
                                   Sum('low_total'))

            low_openvas = scan_save_db.objects. \
                filter(date_time__year=dash_year,
                       date_time__month=m).aggregate(
                           Sum('low_total'))

            for key, value in low_zap.iteritems():
                if value is None:
                    zap_low = '0'
                else:
                    zap_low = value
            for key, value in low_burp.iteritems():
                if value is None:
                    burp_low = '0'
                else:
                    burp_low = value

            for key, value in low_arachni.iteritems():
                if value is None:
                    arachni_low = '0'
                else:
                    arachni_low = value

            for key, value in low_webinspect.iteritems():
                if value is None:
                    webinspect_low = '0'
                else:
                    webinspect_low = value

            for key, value in low_netsparker.iteritems():
                if value is None:
                    netsparker_low = '0'
                else:
                    netsparker_low = value

            for key, value in low_acunetix_low.iteritems():
                if value is None:
                    acunetix_low = '0'
                else:
                    acunetix_low = value

            for key, value in low_nessus.iteritems():
                if value is None:
                    nessus_low = '0'
                else:
                    nessus_low = value

            for key, value in low_openvas.iteritems():
                if value is None:
                    openvas_low = '0'
                else:
                    openvas_low = value
            global data
            all_low_stat = int(zap_low) + \
                int(burp_low) + \
                int(openvas_low) + \
                int(arachni_low) + \
                int(webinspect_low) + \
                int(netsparker_low) + \
                int(acunetix_low) + \
                int(nessus_low)

            data = {m: {'h': all_high_stat,
                        'm': all_medium_stat,
                        'l': all_low_stat}}
            high_list.append(data)
    except Exception as e:
        print "Error got !!!", e

    zap_false_positive = zap_scan_results_db.objects.filter(false_positive='Yes')
    burp_false_positive = burp_scan_result_db.objects.filter(false_positive='Yes')
    arachni_false_positive = arachni_scan_result_db.objects.filter(false_positive='Yes')
    netsparker_false_positive = netsparker_scan_result_db.objects.filter(false_positive='Yes')
    webinspect_false_positive = webinspect_scan_result_db.objects.filter(false_positive='Yes')

    openvas_false_positive = ov_scan_result_db.objects.filter(false_positive='Yes')
    nessus_false_positive = nessus_report_db.objects.filter(false_positive='Yes')

    zap_closed_vuln = zap_scan_results_db.objects.filter(vuln_status='Closed')
    burp_closed_vuln = burp_scan_result_db.objects.filter(vuln_status='Closed')
    arachni_closed_vuln = arachni_scan_result_db.objects.filter(vuln_status='Closed')
    netsparker_closed_vuln = netsparker_scan_result_db.objects.filter(vuln_status='Closed')
    webinspect_closed_vuln = webinspect_scan_result_db.objects.filter(vuln_status='Closed')
    openvas_closed_vuln = ov_scan_result_db.objects.filter(vuln_status='Closed')
    nessus_closed_vuln = nessus_report_db.objects.filter(vuln_status='Closed')

    all_closed_vuln = int(len(zap_closed_vuln)) + \
        int(len(burp_closed_vuln)) + \
        int(len(arachni_closed_vuln)) + \
        int(len(netsparker_closed_vuln)) + \
        int(len(webinspect_closed_vuln)) + \
        int(len(openvas_closed_vuln)) + \
        int(len(nessus_closed_vuln))

    all_false_positive = int(len(zap_false_positive)) + \
        int(len(burp_false_positive)) + \
        int(len(webinspect_false_positive)) + \
        int(len(netsparker_false_positive)) + \
        int(len(arachni_false_positive)) + \
        int(len(openvas_false_positive)) + \
        int(len(nessus_false_positive))

    return render(request, 'dashboard/index.html',

                  {'high_data': high_list,
                   'all_project': all_project,
                   'dash_year': dash_year,
                   'all_vuln': all_vuln,
                   'total_web': total_web,
                   'total_network': total_network,
                   'all_high': all_high,
                   'all_medium': all_medium,
                   'all_low': all_low,
                   'all_web_high': all_web_high,
                   'all_web_medium': all_web_medium,
                   'all_network_medium': all_network_medium,
                   'all_network_high': all_network_high,
                   'all_web_low': all_web_low,
                   'all_network_low': all_network_low,
                   'all_false_positive': all_false_positive,
                   'all_closed_vuln': all_closed_vuln
                   })


def project_dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """
    global all_vuln, \
        total_web, \
        all_high, \
        total_network, \
        all_medium, \
        all_low, \
        all_web_high, \
        all_web_medium, \
        all_network_medium, \
        all_web_low, \
        all_network_low, \
        all_network_high
    all_project = project_db.objects.all()

    return render(request,
                  'dashboard/project.html',
                  {'all_project': all_project})


def proj_data(request):
    """
    The function pulling all project data from database.
    :param request:
    :return:
    """
    all_project = project_db.objects.all()
    if request.GET['project_id']:
        project_id = request.GET['project_id']
    else:
        project_id = ''

    all_zap_scan = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))
    all_openvas_scan = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value
    for key, value in all_burp_scan.iteritems():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value
    for key, value in all_openvas_scan.iteritems():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    all_vuln = int(all_zap) + int(all_burp) + int(all_openvas)

    total_network = all_openvas

    total_web = int(all_zap) + int(all_burp)

    all_zap_high = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))
    all_openvas_high = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_total'))

    for key, value in all_zap_high.iteritems():
        if value is None:
            zap_high = '0'
        else:
            zap_high = value
    for key, value in all_burp_high.iteritems():
        if value is None:
            burp_high = '0'
        else:
            burp_high = value
    for key, value in all_openvas_high.iteritems():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    all_high = int(zap_high) + int(burp_high) + int(openvas_high)
    all_web_high = int(zap_high) + int(burp_high)
    all_network_high = openvas_high

    all_zap_medium = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))
    all_openvas_medium = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_total'))

    for key, value in all_zap_medium.iteritems():
        if value is None:
            zap_medium = '0'
        else:
            zap_medium = value
    for key, value in all_burp_medium.iteritems():
        if value is None:
            burp_medium = '0'
        else:
            burp_medium = value
    for key, value in all_openvas_medium.iteritems():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    all_medium = int(zap_medium) + int(burp_medium) + int(openvas_medium)
    all_web_medium = int(zap_medium) + int(burp_medium)
    all_network_medium = openvas_medium

    all_zap_low = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))
    all_openvas_low = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_total'))

    for key, value in all_zap_low.iteritems():
        if value is None:
            zap_low = '0'
        else:
            zap_low = value
    for key, value in all_burp_low.iteritems():
        if value is None:
            burp_low = '0'
        else:
            burp_low = value
    for key, value in all_openvas_low.iteritems():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    all_low = int(zap_low) + int(burp_low) + int(openvas_low)
    all_web_low = int(zap_low) + int(burp_low)
    all_network_low = openvas_low

    return render(request,
                  'dashboard/project.html',
                  {'all_vuln': all_vuln,
                   'total_web': total_web,
                   'total_network': total_network,
                   'all_high': all_high,
                   'all_medium': all_medium,
                   'all_low': all_low,
                   'all_web_high': all_web_high,
                   'all_web_medium': all_web_medium,
                   'all_network_medium': all_network_medium,
                   'all_network_high': all_network_high,
                   'all_web_low': all_web_low,
                   'all_network_low': all_network_low,
                   'all_project': all_project})


def web_dashboard(request):
    """
    The function calling Web Dashboard.
    :param request:
    :return:
    """
    all_burp_data = burp_scan_db.objects.all()
    all_zap_data = zap_scans_db.objects.all()
    all_arachni_data = arachni_scan_db.objects.all()
    all_netsparker_data = netsparker_scan_db.objects.all()
    all_webinspect_data = webinspect_scan_db.objects.all()
    all_acunetix_data = acunetix_scan_db.objects.all()
    all_web_data = chain(all_burp_data,
                         all_zap_data,
                         all_arachni_data,
                         all_netsparker_data,
                         all_webinspect_data,
                         all_acunetix_data
                         )

    return render(request,
                  'dashboard/web_scan.html',
                  {'all_web_data': all_web_data})


def web_dash_data(request):
    """
    The function pulling all web dashboard data from database.
    :param request:
    :return:
    """
    all_burp_data = burp_scan_db.objects.all()
    all_zap_data = zap_scans_db.objects.all()
    all_netsparker_data = netsparker_scan_db.objects.all()
    all_webinspect_data = webinspect_scan_db.objects.all()
    all_arachni_data = arachni_scan_db.objects.all()
    all_acunetix_data = acunetix_scan_db.objects.all()

    all_web_data = chain(all_burp_data,
                         all_zap_data,
                         all_netsparker_data,
                         all_webinspect_data,
                         all_arachni_data,
                         all_acunetix_data
                         )

    if request.GET['scan_id']:
        scan_id = request.GET['scan_id']

    else:
        scan_id = ''

    all_zap_scan = zap_scans_db.objects.filter(scan_scanid=scan_id) \
        .aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('total_vul'))

    all_netsparker_scan = netsparker_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('total_vul'))

    all_webinspect_scan = webinspect_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('total_vul'))

    all_arachni_scan = arachni_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('total_vul'))

    all_acunetix_scan = acunetix_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value

    for key, value in all_burp_scan.iteritems():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value

    for key, value in all_netsparker_scan.iteritems():
        if value is None:
            all_netsparker = '0'
        else:
            all_netsparker = value

    for key, value in all_webinspect_scan.iteritems():
        if value is None:
            all_webinspect = '0'
        else:
            all_webinspect = value

    for key, value in all_arachni_scan.iteritems():
        if value is None:
            all_arachni = '0'
        else:
            all_arachni = value

    for key, value in all_acunetix_scan.iteritems():
        if value is None:
            all_acunetix = '0'
        else:
            all_acunetix = value

    all_vuln = int(all_zap) + \
        int(all_burp) + \
        int(all_netsparker) + \
        int(all_webinspect) + \
        int(all_arachni) + \
        int(all_acunetix)

    total_web = all_vuln

    all_zap_high = zap_scans_db.objects.filter(scan_scanid=scan_id) \
        .aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('high_vul'))

    all_netsparker_high = netsparker_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('high_vul'))

    all_webinspect_high = webinspect_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('high_vul'))

    all_arachni_high = arachni_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('high_vul'))

    for key, value in all_zap_high.iteritems():
        if value is None:
            all_high_zap = '0'
        else:
            all_high_zap = value
    for key, value in all_burp_high.iteritems():
        if value is None:
            all_high_burp = '0'
        else:
            all_high_burp = value

    for key, value in all_netsparker_high.iteritems():
        if value is None:
            all_high_netsparker = '0'
        else:
            all_high_netsparker = value

    for key, value in all_webinspect_high.iteritems():
        if value is None:
            all_high_webinspect = '0'
        else:
            all_high_webinspect = value

    for key, value in all_arachni_high.iteritems():
        if value is None:
            all_high_arachni = '0'
        else:
            all_high_arachni = value

    all_high = int(all_high_zap) + \
        int(all_high_burp) + \
        int(all_high_netsparker) + \
        int(all_high_webinspect) + \
        int(all_high_arachni)

    all_zap_medium = zap_scans_db.objects.filter(scan_scanid=scan_id) \
        .aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('medium_vul'))

    all_netsparker_medium = netsparker_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('medium_vul'))

    all_webinspect_medium = webinspect_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('medium_vul'))

    all_arachni_medium = arachni_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('medium_vul'))

    for key, value in all_zap_medium.iteritems():
        if value is None:
            all_medium_zap = '0'
        else:
            all_medium_zap = value
    for key, value in all_burp_medium.iteritems():
        if value is None:
            all_medium_burp = '0'
        else:
            all_medium_burp = value

    for key, value in all_netsparker_medium.iteritems():
        if value is None:
            all_medium_netsparker = '0'
        else:
            all_medium_netsparker = value

    for key, value in all_webinspect_medium.iteritems():
        if value is None:
            all_medium_webinspect = '0'
        else:
            all_medium_webinspect = value

    for key, value in all_arachni_medium.iteritems():
        if value is None:
            all_medium_arachni = '0'
        else:
            all_medium_arachni = value

    all_medium = int(all_medium_zap) + \
        int(all_medium_burp) + \
        int(all_medium_netsparker) + \
        int(all_medium_webinspect) + \
        int(all_medium_arachni)

    all_zap_low = zap_scans_db.objects.filter(scan_scanid=scan_id) \
        .aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('low_vul'))

    all_netsparker_low = netsparker_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('low_vul'))

    all_webinspect_low = webinspect_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('low_vul'))

    all_arachni_low = arachni_scan_db.objects.filter(scan_id=scan_id) \
        .aggregate(Sum('low_vul'))

    for key, value in all_zap_low.iteritems():
        if value is None:
            all_low_zap = '0'
        else:
            all_low_zap = value
    for key, value in all_burp_low.iteritems():
        if value is None:
            all_low_burp = '0'
        else:
            all_low_burp = value

    for key, value in all_netsparker_low.iteritems():
        if value is None:
            all_low_netsparker = '0'
        else:
            all_low_netsparker = value

    for key, value in all_webinspect_low.iteritems():
        if value is None:
            all_low_webinspect = '0'
        else:
            all_low_webinspect = value

    for key, value in all_arachni_low.iteritems():
        if value is None:
            all_low_arachni = '0'
        else:
            all_low_arachni = value

    all_low = int(all_low_zap) + \
        int(all_low_burp) + \
        int(all_low_netsparker) + \
        int(all_low_webinspect) + \
        int(all_low_arachni)

    zap_false_positive = zap_scan_results_db.objects.filter(scan_id=scan_id,
                                                            false_positive='Yes')
    burp_false_positive = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                             false_positive='Yes')
    arachni_false_positive = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                                   false_positive='Yes')
    netsparker_false_positive = netsparker_scan_result_db.objects.filter(scan_id=scan_id,
                                                                         false_positive='Yes')
    webinspect_false_positive = webinspect_scan_result_db.objects.filter(scan_id=scan_id,
                                                                         false_positive='Yes')

    all_false_positive = int(len(zap_false_positive)) + \
        int(len(burp_false_positive)) + \
        int(len(webinspect_false_positive)) + \
        int(len(netsparker_false_positive)) + \
        int(len(arachni_false_positive))

    zap_closed_vuln = zap_scan_results_db.objects.filter(scan_id=scan_id,
                                                         vuln_status='Closed')
    burp_closed_vuln = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                          vuln_status='Closed')
    arachni_closed_vuln = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                                vuln_status='Closed')
    netsparker_closed_vuln = netsparker_scan_result_db.objects.filter(scan_id=scan_id,
                                                                      vuln_status='Closed')
    webinspect_closed_vuln = webinspect_scan_result_db.objects.filter(scan_id=scan_id,
                                                                      vuln_status='Closed')

    all_closed_vuln = int(len(zap_closed_vuln)) + \
        int(len(burp_closed_vuln)) + \
        int(len(webinspect_closed_vuln)) + \
        int(len(netsparker_closed_vuln)) + \
        int(len(arachni_closed_vuln))

    return render(request,
                  'dashboard/web_scan.html',
                  {'all_web_data': all_web_data,
                   'total_web': total_web,
                   'all_high': all_high,
                   'all_medium': all_medium,
                   'all_low': all_low,
                   'all_false_positive': all_false_positive,
                   'all_closed_vuln': all_closed_vuln
                   })


def net_dashboard(request):
    """
    Network vulnerability Dashboard.
    :param request:
    :return:
    """
    all_openvas_data = scan_save_db.objects.all()
    all_nessus_data = nessus_scan_db.objects.all()
    all_network_data = chain(all_openvas_data,
                             all_nessus_data
                             )
    return render(request,
                  'dashboard/network_scan.html',
                  {'all_network_data': all_network_data})


def net_dash_data(request):
    """
    Pulling network dashboard data from database.
    :param request:
    :return:
    """
    all_openvas_data = scan_save_db.objects.all()
    all_nessus_data = nessus_scan_db.objects.all()
    all_network_data = chain(all_openvas_data,
                             all_nessus_data
                             )

    if request.GET['scan_id']:
        scan_id = request.GET['scan_id']

    else:
        scan_id = ''

    all_openvas_scan = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('total_vul'))
    all_nessus_scan = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('total_vul'))

    for key, value in all_openvas_scan.iteritems():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    for key, value in all_nessus_scan.iteritems():
        if value is None:
            all_nessus = '0'
        else:
            all_nessus = value

    total_network = int(all_openvas) + int(all_nessus)

    all_openvas_high = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_total'))
    all_nessus_high = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_total'))

    for key, value in all_openvas_high.iteritems():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    for key, value in all_nessus_high.iteritems():
        if value is None:
            nessus_high = '0'
        else:
            nessus_high = value

    all_network_high = int(openvas_high) + int(nessus_high)

    all_openvas_medium = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_total'))
    all_nessus_medium = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_total'))

    for key, value in all_openvas_medium.iteritems():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    for key, value in all_nessus_medium.iteritems():
        if value is None:
            nessus_medium = '0'
        else:
            nessus_medium = value

    all_network_medium = int(openvas_medium) + int(nessus_medium)

    all_openvas_low = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_total'))
    all_nessus_low = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_total'))

    for key, value in all_openvas_low.iteritems():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    for key, value in all_nessus_low.iteritems():
        if value is None:
            nessus_low = '0'
        else:
            nessus_low = value

    all_network_low = int(openvas_low) + int(nessus_low)

    openvas_false_positive = ov_scan_result_db.objects.filter(scan_id=scan_id,
                                                              false_positive='Yes')
    nessus_false_positive = nessus_report_db.objects.filter(scan_id=scan_id,
                                                            false_positive='Yes')

    all_false_positive = int(len(openvas_false_positive)) + \
        int(len(nessus_false_positive))

    openvas_closed_vuln = ov_scan_result_db.objects.filter(scan_id=scan_id,
                                                           vuln_status='Closed')
    nessus_closed_vuln = nessus_report_db.objects.filter(scan_id=scan_id,
                                                         vuln_status='Closed')

    all_closed_vuln = int(len(openvas_closed_vuln)) + \
        int(len(nessus_closed_vuln))

    return render(request,
                  'dashboard/network_scan.html',
                  {'all_network_data': all_network_data,
                   'total_network': total_network,
                   'all_network_high': all_network_high,
                   'all_network_medium': all_network_medium,
                   'all_network_low': all_network_low,
                   'all_false_positive': all_false_positive,
                   'all_closed_vuln': all_closed_vuln
                   })
