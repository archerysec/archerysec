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


""" Author: Anand Tiwari """

from __future__ import unicode_literals

from django.db.models import Sum
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
    acunetix_scan_db, acunetix_scan_result_db
from manual_scan.models import manual_scans_db, manual_scan_results_db

from staticscanners.models import dependencycheck_scan_db, \
    bandit_scan_db, bandit_scan_results_db, \
    findbugs_scan_db, \
    dependencycheck_scan_results_db, \
    findbugs_scan_results_db, clair_scan_results_db, clair_scan_db
from networkscanners.models import scan_save_db, \
    nessus_scan_db, \
    ov_scan_result_db, \
    nessus_report_db
from compliance.models import inspec_scan_db, inspec_scan_results_db
from projects.models import project_db
from django.shortcuts import render, render_to_response, HttpResponse, HttpResponseRedirect
from itertools import chain
import datetime
from webscanners.resources import AllResource
from notifications.models import Notification
from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def dashboard(request):
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

    scanners = 'vscanners'
    all_project = project_db.objects.all()

    user = user_logged_in
    all_notify = Notification.objects.unread()

    return render(request,
                  'dashboard/index.html',
                  {'all_project': all_project,
                   'scanners': scanners,
                   'message': all_notify
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

    scanners = 'vscanners'
    all_project = project_db.objects.all()

    all_notify = Notification.objects.unread()

    return render(request,
                  'dashboard/project.html',
                  {'all_project': all_project,
                   'scanners': scanners,
                   'message': all_notify
                   })


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

    all_arachni_scan = arachni_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_netsparker_scan = netsparker_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_webinspect_scan = webinspect_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_acunetix_scan = acunetix_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_dependency_scan = dependencycheck_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_findbugs_scan = findbugs_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_clair_scan = clair_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_inspec_scan = inspec_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_bandit_scan = bandit_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_openvas_scan = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_nessus_scan = nessus_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_manual_scan = manual_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.items():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value
    for key, value in all_burp_scan.items():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value

    for key, value in all_arachni_scan.items():
        if value is None:
            all_arachni = '0'
        else:
            all_arachni = value

    for key, value in all_netsparker_scan.items():
        if value is None:
            all_netsparker = '0'
        else:
            all_netsparker = value

    for key, value in all_acunetix_scan.items():
        if value is None:
            all_acunetix = '0'
        else:
            all_acunetix = value

    for key, value in all_webinspect_scan.items():
        if value is None:
            all_webinspect = '0'
        else:
            all_webinspect = value

    for key, value in all_dependency_scan.items():
        if value is None:
            all_dependency = '0'
        else:
            all_dependency = value

    for key, value in all_findbugs_scan.items():
        if value is None:
            all_findbugs = '0'
        else:
            all_findbugs = value

    for key, value in all_clair_scan.items():
        if value is None:
            all_clair = '0'
        else:
            all_clair = value

    for key, value in all_inspec_scan.items():
        if value is None:
            all_inspec = '0'
        else:
            all_inspec = value

    for key, value in all_bandit_scan.items():
        if value is None:
            all_bandit = '0'
        else:
            all_bandit = value

    for key, value in all_nessus_scan.items():
        if value is None:
            all_nessus = '0'
        else:
            all_nessus = value

    for key, value in all_openvas_scan.items():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    for key, value in all_manual_scan.items():
        if value is None:
            all_manual = '0'
        else:
            all_manual = value

    all_pentest_web = manual_scans_db.objects.filter(pentest_type='web', project_id=project_id). \
        aggregate(Sum('total_vul'))

    for key, value in all_pentest_web.items():
        if value is None:
            pentest_web = '0'
        else:
            pentest_web = value

    all_pentest_net = manual_scans_db.objects.filter(pentest_type='network', project_id=project_id). \
        aggregate(Sum('total_vul'))

    for key, value in all_pentest_net.items():
        if value is None:
            pentest_net = '0'
        else:
            pentest_net = value

    all_vuln = int(all_zap) + \
               int(all_burp) + \
               int(all_openvas) + \
               int(all_arachni) + \
               int(all_netsparker) + \
               int(all_acunetix) + \
               int(all_webinspect) + \
               int(all_dependency) + \
               int(all_findbugs) + \
               int(all_clair) + \
               int(all_bandit) + \
               int(all_manual)

    total_network = int(all_openvas) + int(all_nessus) + int(pentest_net)

    total_web = int(all_zap) + int(all_burp) + int(pentest_web) + int(all_arachni) + \
                int(all_netsparker) + int(all_webinspect) + int(all_acunetix)

    total_compliance = int(all_inspec)

    total_static = int(all_dependency) + int(all_findbugs) + int(all_bandit) + int(all_clair)

    all_zap_high = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_arachni_high = arachni_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_netsparker_high = netsparker_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_webinspect_high = webinspect_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_acunetix_high = acunetix_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_dependency_high = dependencycheck_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_findbugs_high = findbugs_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_clair_high = clair_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_inspec_failed = inspec_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('inspec_failed'))

    all_bandit_high = bandit_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_nessus_high = nessus_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_total'))

    all_openvas_high = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_total'))

    all_pentest_high = manual_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('high_vul'))

    for key, value in all_zap_high.items():
        if value is None:
            zap_high = '0'
        else:
            zap_high = value
    for key, value in all_burp_high.items():
        if value is None:
            burp_high = '0'
        else:
            burp_high = value

    for key, value in all_arachni_high.items():
        if value is None:
            high_arachni = '0'
        else:
            high_arachni = value

    for key, value in all_netsparker_high.items():
        if value is None:
            high_netsparker = '0'
        else:
            high_netsparker = value

    for key, value in all_acunetix_high.items():
        if value is None:
            high_acunetix = '0'
        else:
            high_acunetix = value

    for key, value in all_webinspect_high.items():
        if value is None:
            high_webinspect = '0'
        else:
            high_webinspect = value

    for key, value in all_dependency_high.items():
        if value is None:
            high_dependency = '0'
        else:
            high_dependency = value

    for key, value in all_findbugs_high.items():
        if value is None:
            high_findbugs = '0'
        else:
            high_findbugs = value

    for key, value in all_clair_high.items():
        if value is None:
            high_clair = '0'
        else:
            high_clair = value

    for key, value in all_inspec_failed.items():
        if value is None:
            failed_inspec = '0'
        else:
            failed_inspec = value

    for key, value in all_bandit_high.items():
        if value is None:
            high_bandit = '0'
        else:
            high_bandit = value

    for key, value in all_nessus_high.items():
        if value is None:
            high_nessus = '0'
        else:
            high_nessus = value

    for key, value in all_openvas_high.items():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    for key, value in all_pentest_high.items():
        if value is None:
            pentest_high = '0'
        else:
            pentest_high = value

    all_high_pentest_web = manual_scans_db.objects.filter(pentest_type='web', project_id=project_id). \
        aggregate(Sum('high_vul'))

    for key, value in all_high_pentest_web.items():
        if value is None:
            high_pentest_web = '0'
        else:
            high_pentest_web = value

    all_high_pentest_net = manual_scans_db.objects.filter(pentest_type='network', project_id=project_id). \
        aggregate(Sum('high_vul'))

    for key, value in all_high_pentest_net.items():
        if value is None:
            high_pentest_net = '0'
        else:
            high_pentest_net = value

    all_high = int(zap_high) + \
               int(burp_high) + \
               int(openvas_high) + \
               int(high_arachni) + \
               int(high_netsparker) + \
               int(high_acunetix) + \
               int(high_webinspect) + \
               int(high_dependency) + \
               int(high_findbugs) + \
               int(high_clair) + \
               int(high_bandit) + \
               int(high_nessus) + \
               int(pentest_high)

    all_web_high = int(zap_high) + \
                   int(burp_high) + \
                   int(high_arachni) + \
                   int(high_netsparker) + \
                   int(high_acunetix) + \
                   int(high_webinspect) + int(high_pentest_web)

    all_static_high = int(high_dependency) + \
                      int(high_findbugs) + \
                      int(high_bandit)

    all_network_high = int(openvas_high) + int(high_nessus) + int(high_pentest_net)

    all_compliance_failed = int(failed_inspec)

    all_zap_medium = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_arachni_medium = arachni_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_netsparker_medium = netsparker_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_webinspect_medium = webinspect_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_acunetix_medium = acunetix_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_dependency_medium = dependencycheck_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_findbugs_medium = findbugs_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_clair_medium = clair_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_inspec_passed = inspec_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('inspec_passed'))

    all_bandit_medium = bandit_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_nessus_medium = nessus_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_total'))

    all_openvas_medium = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_total'))
    all_pentest_medium = manual_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('medium_vul'))

    for key, value in all_zap_medium.items():
        if value is None:
            zap_medium = '0'
        else:
            zap_medium = value
    for key, value in all_burp_medium.items():
        if value is None:
            burp_medium = '0'
        else:
            burp_medium = value

    for key, value in all_arachni_medium.items():
        if value is None:
            medium_arachni = '0'
        else:
            medium_arachni = value

    for key, value in all_netsparker_medium.items():
        if value is None:
            medium_netsparker = '0'
        else:
            medium_netsparker = value

    for key, value in all_acunetix_medium.items():
        if value is None:
            medium_acunetix = '0'
        else:
            medium_acunetix = value

    for key, value in all_webinspect_medium.items():
        if value is None:
            medium_webinspect = '0'
        else:
            medium_webinspect = value

    for key, value in all_dependency_medium.items():
        if value is None:
            medium_dependency = '0'
        else:
            medium_dependency = value

    for key, value in all_findbugs_medium.items():
        if value is None:
            medium_findbugs = '0'
        else:
            medium_findbugs = value

    for key, value in all_clair_medium.items():
        if value is None:
            medium_clair = '0'
        else:
            medium_clair = value

    for key, value in all_inspec_passed.items():
        if value is None:
            passed_inspec = '0'
        else:
            passed_inspec = value

    for key, value in all_bandit_medium.items():
        if value is None:
            medium_bandit = '0'
        else:
            medium_bandit = value

    for key, value in all_nessus_medium.items():
        if value is None:
            medium_nessus = '0'
        else:
            medium_nessus = value

    for key, value in all_openvas_medium.items():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    for key, value in all_pentest_medium.items():
        if value is None:
            pentest_medium = '0'
        else:
            pentest_medium = value

    all_medium = int(zap_medium) + \
                 int(burp_medium) + \
                 int(openvas_medium) + \
                 int(medium_arachni) + \
                 int(medium_netsparker) + \
                 int(medium_acunetix) + \
                 int(medium_webinspect) + \
                 int(medium_dependency) + \
                 int(medium_findbugs) + \
                 int(medium_clair) + \
                 int(medium_bandit) + \
                 int(medium_nessus) + \
                 int(pentest_medium)

    all_medium_pentest_web = manual_scans_db.objects.filter(pentest_type='web', project_id=project_id). \
        aggregate(Sum('medium_vul'))

    for key, value in all_medium_pentest_web.items():
        if value is None:
            medium_pentest_web = '0'
        else:
            medium_pentest_web = value

    all_medium_pentest_net = manual_scans_db.objects.filter(pentest_type='network', project_id=project_id). \
        aggregate(Sum('medium_vul'))

    for key, value in all_medium_pentest_net.items():
        if value is None:
            medium_pentest_net = '0'
        else:
            medium_pentest_net = value

    all_web_medium = int(zap_medium) + \
                     int(burp_medium) + \
                     int(medium_arachni) + \
                     int(medium_netsparker) + \
                     int(medium_acunetix) + \
                     int(medium_webinspect) + int(medium_pentest_web)

    all_static_medium = int(medium_dependency) + \
                        int(medium_findbugs) + \
                        int(medium_bandit)

    all_network_medium = int(openvas_medium) + int(medium_pentest_net) + int(medium_nessus)

    all_compliance_passed = int(passed_inspec)

    all_zap_low = zap_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_arachni_low = arachni_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_netsparker_low = netsparker_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_webinspect_low = webinspect_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_acunetix_low = acunetix_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_dependency_low = dependencycheck_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_findbugs_low = findbugs_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_clair_low = clair_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_inspec_skipped = inspec_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('inspec_skipped'))

    all_bandit_low = bandit_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_nessus_low = nessus_scan_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_total'))

    all_openvas_low = scan_save_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_total'))

    all_pentest_low = manual_scans_db.objects.filter(project_id=project_id). \
        aggregate(Sum('low_vul'))

    for key, value in all_zap_low.items():
        if value is None:
            zap_low = '0'
        else:
            zap_low = value
    for key, value in all_burp_low.items():
        if value is None:
            burp_low = '0'
        else:
            burp_low = value

    for key, value in all_arachni_low.items():
        if value is None:
            low_arachni = '0'
        else:
            low_arachni = value

    for key, value in all_netsparker_low.items():
        if value is None:
            low_netsparker = '0'
        else:
            low_netsparker = value

    for key, value in all_acunetix_low.items():
        if value is None:
            low_acunetix = '0'
        else:
            low_acunetix = value

    for key, value in all_webinspect_low.items():
        if value is None:
            low_webinspect = '0'
        else:
            low_webinspect = value

    for key, value in all_dependency_low.items():
        if value is None:
            low_dependency = '0'
        else:
            low_dependency = value

    for key, value in all_findbugs_low.items():
        if value is None:
            low_findbugs = '0'
        else:
            low_findbugs = value

    for key, value in all_clair_low.items():
        if value is None:
            low_clair = '0'
        else:
            low_clair = value

    for key, value in all_inspec_skipped.items():
        if value is None:
            skipped_inspec = '0'
        else:
            skipped_inspec = value

    for key, value in all_bandit_low.items():
        if value is None:
            low_bandit = '0'
        else:
            low_bandit = value

    for key, value in all_nessus_low.items():
        if value is None:
            low_nessus = '0'
        else:
            low_nessus = value

    for key, value in all_openvas_low.items():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    for key, value in all_pentest_low.items():
        if value is None:
            pentest_low = '0'
        else:
            pentest_low = value

    all_low = int(zap_low) + \
              int(burp_low) + \
              int(openvas_low) + \
              int(low_arachni) + \
              int(low_netsparker) + \
              int(low_acunetix) + \
              int(low_webinspect) + \
              int(low_dependency) + \
              int(low_findbugs) + \
              int(low_clair) + \
              int(low_bandit) + \
              int(low_nessus) + \
              int(pentest_low)

    all_low_pentest_web = manual_scans_db.objects.filter(pentest_type='web', project_id=project_id). \
        aggregate(Sum('low_vul'))

    for key, value in all_low_pentest_web.items():
        if value is None:
            low_pentest_web = '0'
        else:
            low_pentest_web = value

    all_low_pentest_net = manual_scans_db.objects.filter(pentest_type='network', project_id=project_id). \
        aggregate(Sum('low_vul'))

    for key, value in all_low_pentest_net.items():
        if value is None:
            low_pentest_net = '0'
        else:
            low_pentest_net = value

    all_web_low = int(zap_low) + \
                  int(burp_low) + \
                  int(low_arachni) + \
                  int(low_netsparker) + \
                  int(low_acunetix) + \
                  int(low_webinspect) + int(low_pentest_web)

    all_static_low = int(low_dependency) + \
                     int(low_findbugs) + \
                     int(low_bandit)

    all_network_low = int(openvas_low) + int(low_nessus) + int(low_pentest_net)

    all_compliance_skipped = int(skipped_inspec)

    project_dat = project_db.objects.filter(project_id=project_id)
    burp = burp_scan_db.objects.filter(project_id=project_id)
    zap = zap_scans_db.objects.filter(project_id=project_id)
    arachni = arachni_scan_db.objects.filter(project_id=project_id)
    webinspect = webinspect_scan_db.objects.filter(project_id=project_id)
    netsparker = netsparker_scan_db.objects.filter(project_id=project_id)
    acunetix = acunetix_scan_db.objects.filter(project_id=project_id)

    dependency_check = dependencycheck_scan_db.objects.filter(project_id=project_id)
    findbugs = findbugs_scan_db.objects.filter(project_id=project_id)
    clair = clair_scan_db.objects.filter(project_id=project_id)
    bandit = bandit_scan_db.objects.filter(project_id=project_id)

    web_scan_dat = chain(burp, zap, arachni, webinspect, netsparker, acunetix)
    static_scan = chain(dependency_check, findbugs)
    openvas_dat = scan_save_db.objects.filter(project_id=project_id)
    nessus_dat = nessus_scan_db.objects.filter(project_id=project_id)

    network_dat = chain(openvas_dat, nessus_dat)

    inspec = inspec_scan_db.objects.filter(project_id=project_id)
    compliance_dat = chain(inspec)

    all_compliance = inspec_scan_db.objects.filter(project_id=project_id)

    pentest = manual_scans_db.objects.filter(project_id=project_id)

    zap_false_positive = zap_scan_results_db.objects.filter(false_positive='Yes', project_id=project_id)
    burp_false_positive = burp_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)
    arachni_false_positive = arachni_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)
    netsparker_false_positive = netsparker_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)
    webinspect_false_positive = webinspect_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)
    acunetix_false_positive = acunetix_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)

    dependencycheck_false_positive = dependencycheck_scan_results_db.objects.filter(false_positive='Yes',
                                                                                    project_id=project_id)
    findbugs_false_positive = findbugs_scan_results_db.objects.filter(false_positive='Yes', project_id=project_id)
    clair_false_positive = clair_scan_results_db.objects.filter(false_positive='Yes', project_id=project_id)

    openvas_false_positive = ov_scan_result_db.objects.filter(false_positive='Yes', project_id=project_id)
    nessus_false_positive = nessus_report_db.objects.filter(false_positive='Yes', project_id=project_id)

    zap_closed_vuln = zap_scan_results_db.objects.filter(vuln_status='Closed', project_id=project_id)
    burp_closed_vuln = burp_scan_result_db.objects.filter(vuln_status='Closed', project_id=project_id)
    arachni_closed_vuln = arachni_scan_result_db.objects.filter(vuln_status='Closed', project_id=project_id)
    netsparker_closed_vuln = netsparker_scan_result_db.objects.filter(vuln_status='Closed', project_id=project_id)
    webinspect_closed_vuln = webinspect_scan_result_db.objects.filter(vuln_status='Closed', project_id=project_id)
    openvas_closed_vuln = ov_scan_result_db.objects.filter(vuln_status='Closed', project_id=project_id)
    nessus_closed_vuln = nessus_report_db.objects.filter(vuln_status='Closed', project_id=project_id)

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
                         int(len(nessus_false_positive)) + \
                         int(len(acunetix_false_positive)) + \
                         int(len(dependencycheck_false_positive)) + \
                         int(len(findbugs_false_positive)) + \
                         int(len(clair_false_positive))

    all_notify = Notification.objects.unread()

    total = all_high, all_medium, all_low

    tota_vuln = sum(total)

    return render(request,
                  'dashboard/project.html',
                  {'project_id': project_id,
                   'tota_vuln': tota_vuln,
                   'all_vuln': all_vuln,
                   'total_web': total_web,
                   'total_static': total_static,
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
                   'all_project': all_project,
                   'project_dat': project_dat,
                   'web_scan_dat': web_scan_dat,
                   'all_static_high': all_static_high,
                   'all_static_medium': all_static_medium,
                   'all_static_low': all_static_low,
                   'static_scan': static_scan,
                   'zap': zap,
                   'burp': burp,
                   'arachni': arachni,
                   'webinspect': webinspect,
                   'netsparker': netsparker,
                   'acunetix': acunetix,
                   'dependency_check': dependency_check,
                   'findbugs': findbugs,
                   'bandit': bandit,
                   'clair': clair,
                   'pentest': pentest,
                   'network_dat': network_dat,
                   'all_zap_scan': all_zap_scan,
                   'all_burp_scan': all_burp_scan,
                   'all_arachni_scan': all_arachni_scan,
                   'all_acunetix_scan': all_acunetix_scan,
                   'all_netsparker_scan': all_netsparker_scan,
                   'all_openvas_scan': all_openvas_scan,
                   'all_nessus_scan': all_nessus_scan,
                   'all_dependency_scan': all_dependency_scan,
                   'all_findbugs_scan': all_findbugs_scan,
                   'all_clair_scan': all_clair_scan,
                   'all_webinspect_scan': all_webinspect_scan,

                   'all_compliance_failed': all_compliance_failed,
                   'all_compliance_passed': all_compliance_passed,
                   'all_compliance_skipped': all_compliance_skipped,
                   'total_compliance': total_compliance,

                   'openvas_dat': openvas_dat,
                   'nessus_dat': nessus_dat,

                   'all_compliance': all_compliance,

                   'compliance_dat': compliance_dat,

                   'all_zap_high': all_zap_high,
                   'all_zap_low': all_zap_low,
                   'all_zap_medium': all_zap_medium,

                   'all_webinspect_high': all_webinspect_high,
                   'all_webinspect_low': all_webinspect_low,
                   'all_webinspect_medium': all_webinspect_medium,

                   'all_acunetix_high': all_acunetix_high,
                   'all_acunetix_low': all_acunetix_low,
                   'all_acunetix_medium': all_acunetix_medium,

                   'all_burp_high': all_burp_high,
                   'all_burp_low': all_burp_low,
                   'all_burp_medium': all_burp_medium,

                   'all_arachni_high': all_arachni_high,
                   'all_arachni_low': all_arachni_low,
                   'all_arachni_medium': all_arachni_medium,

                   'all_netsparker_high': all_netsparker_high,
                   'all_netsparker_low': all_netsparker_low,
                   'all_netsparker_medium': all_netsparker_medium,

                   'all_openvas_high': all_openvas_high,
                   'all_openvas_low': all_openvas_low,
                   'all_openvas_medium': all_openvas_medium,

                   'all_nessus_high': all_nessus_high,
                   'all_nessus_low': all_nessus_low,
                   'all_nessus_medium': all_nessus_medium,

                   'all_dependency_high': all_dependency_high,
                   'all_dependency_low': all_dependency_low,
                   'all_dependency_medium': all_dependency_medium,

                   'all_findbugs_high': all_findbugs_high,
                   'all_findbugs_low': all_findbugs_low,
                   'all_findbugs_medium': all_findbugs_medium,

                   'all_bandit_high': all_bandit_high,
                   'all_bandit_low': all_bandit_low,
                   'all_bandit_medium': all_bandit_medium,

                   'all_clair_high': all_clair_high,
                   'all_clair_low': all_clair_low,
                   'all_clair_medium': all_clair_medium,

                   'all_closed_vuln': all_closed_vuln,
                   'all_false_positive': all_false_positive,
                   'message': all_notify
                   })


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

    for key, value in all_zap_scan.items():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value

    for key, value in all_burp_scan.items():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value

    for key, value in all_netsparker_scan.items():
        if value is None:
            all_netsparker = '0'
        else:
            all_netsparker = value

    for key, value in all_webinspect_scan.items():
        if value is None:
            all_webinspect = '0'
        else:
            all_webinspect = value

    for key, value in all_arachni_scan.items():
        if value is None:
            all_arachni = '0'
        else:
            all_arachni = value

    for key, value in all_acunetix_scan.items():
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

    for key, value in all_zap_high.items():
        if value is None:
            all_high_zap = '0'
        else:
            all_high_zap = value
    for key, value in all_burp_high.items():
        if value is None:
            all_high_burp = '0'
        else:
            all_high_burp = value

    for key, value in all_netsparker_high.items():
        if value is None:
            all_high_netsparker = '0'
        else:
            all_high_netsparker = value

    for key, value in all_webinspect_high.items():
        if value is None:
            all_high_webinspect = '0'
        else:
            all_high_webinspect = value

    for key, value in all_arachni_high.items():
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

    for key, value in all_zap_medium.items():
        if value is None:
            all_medium_zap = '0'
        else:
            all_medium_zap = value
    for key, value in all_burp_medium.items():
        if value is None:
            all_medium_burp = '0'
        else:
            all_medium_burp = value

    for key, value in all_netsparker_medium.items():
        if value is None:
            all_medium_netsparker = '0'
        else:
            all_medium_netsparker = value

    for key, value in all_webinspect_medium.items():
        if value is None:
            all_medium_webinspect = '0'
        else:
            all_medium_webinspect = value

    for key, value in all_arachni_medium.items():
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

    for key, value in all_zap_low.items():
        if value is None:
            all_low_zap = '0'
        else:
            all_low_zap = value
    for key, value in all_burp_low.items():
        if value is None:
            all_low_burp = '0'
        else:
            all_low_burp = value

    for key, value in all_netsparker_low.items():
        if value is None:
            all_low_netsparker = '0'
        else:
            all_low_netsparker = value

    for key, value in all_webinspect_low.items():
        if value is None:
            all_low_webinspect = '0'
        else:
            all_low_webinspect = value

    for key, value in all_arachni_low.items():
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

    for key, value in all_openvas_scan.items():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    for key, value in all_nessus_scan.items():
        if value is None:
            all_nessus = '0'
        else:
            all_nessus = value

    total_network = int(all_openvas) + int(all_nessus)

    all_openvas_high = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_total'))
    all_nessus_high = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_total'))

    for key, value in all_openvas_high.items():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    for key, value in all_nessus_high.items():
        if value is None:
            nessus_high = '0'
        else:
            nessus_high = value

    all_network_high = int(openvas_high) + int(nessus_high)

    all_openvas_medium = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_total'))
    all_nessus_medium = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_total'))

    for key, value in all_openvas_medium.items():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    for key, value in all_nessus_medium.items():
        if value is None:
            nessus_medium = '0'
        else:
            nessus_medium = value

    all_network_medium = int(openvas_medium) + int(nessus_medium)

    all_openvas_low = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_total'))
    all_nessus_low = nessus_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_total'))

    for key, value in all_openvas_low.items():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    for key, value in all_nessus_low.items():
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


def all_high_vuln(request):
    all_notify = Notification.objects.unread()
    if request.GET['project_id']:
        project_id = request.GET['project_id']
        severity = request.GET['severity']
    else:
        project_id = ''
        severity = ''

    if severity == 'High':

        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          risk='High')
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 severity='high')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity_name__in=[
                                                                           'Critical', 'High'])

        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity='High')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   VulnSeverity='High')
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           severity='High')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  severity='High')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='High', project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='HIGH', project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(Severity='High', project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(threat='High', project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(risk_factor='High', project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(severity='High', project_id=project_id)

    elif severity == 'Medium':

        # All Medium

        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          risk='Medium')
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 severity='Medium')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity_name__in=[
                                                                           'Medium'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity='Medium')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   VulnSeverity='Medium')
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           severity='Medium')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  severity='Medium')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='Medium', project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='MEDIUM', project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(Severity='Medium', project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(threat='Medium', project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(risk_factor='Medium', project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(severity='Medium', project_id=project_id)

    # All Low
    elif severity == 'Low':

        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          risk='Low')
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 severity='Low')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity_name__in=[
                                                                           'Low'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       severity='Low')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   VulnSeverity='Low')
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           severity='Low')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  severity='Low')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='Low', project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='LOW', project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(Severity='Low', project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(threat='Low', project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(risk_factor='Low', project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(severity='Low', project_id=project_id)

    elif severity == 'Total':
        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          )
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 )
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       )

        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       )
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   )
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(project_id=project_id)

    elif severity == 'False':
        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          false_positive='Yes')
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 false_positive='Yes')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       false_positive='Yes')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       false_positive='Yes')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   false_positive='Yes')
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           false_positive='Yes')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  false_positive='Yes')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id, false_positive='Yes')
        bandit_all_high = bandit_scan_results_db.objects.filter(false_positive='Yes', project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id, false_positive='Yes')

        openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id, false_positive='Yes')
        nessus_all_high = nessus_report_db.objects.filter(project_id=project_id, false_positive='Yes')

        pentest_all_high = ''

    elif severity == 'Close':
        zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                          vuln_status='Closed')
        arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                 vuln_status='Closed')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                       vuln_status='Closed')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                       vuln_status='Closed')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                   vuln_status='Closed')
        burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                           vuln_status='Closed')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                  vuln_status='Closed')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id, vuln_status='Closed')
        bandit_all_high = bandit_scan_results_db.objects.filter(vuln_status='Closed', project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id, vuln_status='Closed')

        openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id, vuln_status='Closed')
        nessus_all_high = nessus_report_db.objects.filter(project_id=project_id, vuln_status='Closed')

        pentest_all_high = ''

    else:
        return HttpResponseRedirect('/proj_data/?project_id=%s' % project_id)

    return render(request,
                  'dashboard/all_high_vuln.html',
                  {'zap_all_high': zap_all_high,
                   'arachni_all_high': arachni_all_high,
                   'webinspect_all_high': webinspect_all_high,
                   'netsparker_all_high': netsparker_all_high,
                   'acunetix_all_high': acunetix_all_high,
                   'burp_all_high': burp_all_high,
                   'dependencycheck_all_high': dependencycheck_all_high,
                   'findbugs_all_high': findbugs_all_high,
                   'bandit_all_high': bandit_all_high,
                   'clair_all_high': clair_all_high,
                   'openvas_all_high': openvas_all_high,
                   'nessus_all_high': nessus_all_high,
                   'project_id': project_id,
                   'severity': severity,
                   'pentest_all_high': pentest_all_high,
                   'message': all_notify,
                   })


def export(request):
    """
    :param request:
    :return:
    """
    dataset = None
    pentest_all_high = None

    if request.method == 'POST':
        project_id = request.POST.get("project_id")
        report_type = request.POST.get("type")
        severity = request.POST.get("severity")

        resource = AllResource()

        if severity == 'High':

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              risk='High')
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     severity='high')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity_name__in=[
                                                                               'Critical', 'High'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity='High')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       VulnSeverity='High')
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               severity='High')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      severity='High')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='High', project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='High', project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(Severity='High', project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(threat='High', project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(risk_factor='High', project_id=project_id)

            pentest_all_high = manual_scan_results_db.objects.filter(severity='High', project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             pentest_all_high,
                             bandit_all_high
                             )

        elif severity == 'Medium':
            # All Medium

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              risk='Medium')
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     severity='Medium')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity_name__in=[
                                                                               'Medium'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity='Medium')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       VulnSeverity='Medium')
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               severity='Medium')
            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      severity='Medium')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='Medium', project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='Medium', project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(Severity='Medium', project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(threat='Medium', project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(risk_factor='Medium', project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(severity='Medium', project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

            # dataset = resource.export(all_data)

        elif severity == 'Low':

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              risk='Low')
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     severity='Low')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity_name__in=[
                                                                               'Low'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           severity='Low')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       VulnSeverity='Low')
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               severity='Low')
            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      severity='Low')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(risk='Low', project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(issue_severity='Low', project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(Severity='Low', project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(threat='Low', project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(risk_factor='Low', project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(severity='Low', project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

            # dataset = resource.export(all_data)

        elif severity == 'Total':

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              )
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     )
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           )

            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           )
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       )
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               )

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      )
            findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

        elif severity == 'False':

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              false_positive='Yes')
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     false_positive='Yes')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           false_positive='Yes')

            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           false_positive='Yes')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       false_positive='Yes')
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               false_positive='Yes')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      false_positive='Yes')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id, false_positive='Yes')
            clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id, false_positive='Yes')

            openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id, false_positive='Yes')
            nessus_all_high = nessus_report_db.objects.filter(project_id=project_id, false_positive='Yes')

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high
                             )

        elif severity == 'Close':

            zap_all_high = zap_scan_results_db.objects.filter(project_id=project_id,
                                                              vuln_status='Closed')
            arachni_all_high = arachni_scan_result_db.objects.filter(project_id=project_id,
                                                                     vuln_status='Closed')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(project_id=project_id,
                                                                           vuln_status='Closed')

            netsparker_all_high = netsparker_scan_result_db.objects.filter(project_id=project_id,
                                                                           vuln_status='Closed')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(project_id=project_id,
                                                                       vuln_status='Closed')
            burp_all_high = burp_scan_result_db.objects.filter(project_id=project_id,
                                                               vuln_status='Closed')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(project_id=project_id,
                                                                                      vuln_status='Closed')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(project_id=project_id, vuln_status='Closed')
            clair_all_high = clair_scan_results_db.objects.filter(project_id=project_id, vuln_status='Closed')

            openvas_all_high = ov_scan_result_db.objects.filter(project_id=project_id, vuln_status='Closed')
            nessus_all_high = nessus_report_db.objects.filter(project_id=project_id, vuln_status='Closed')

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high
                             )

        else:
            return HttpResponseRedirect('/proj_data/?project_id=%s' % project_id)

        dataset = resource.export(all_data)

        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % project_id
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % project_id
            return response
