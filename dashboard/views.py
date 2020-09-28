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
    findbugs_scan_results_db, \
    clair_scan_results_db, \
    clair_scan_db, \
    trivy_scan_results_db, \
    trivy_scan_db, \
    npmaudit_scan_db, \
    npmaudit_scan_results_db, \
    nodejsscan_scan_db, \
    nodejsscan_scan_results_db, \
    semgrepscan_scan_db, \
    semgrepscan_scan_results_db, \
    tfsec_scan_db, \
    tfsec_scan_results_db, \
    whitesource_scan_db, \
    whitesource_scan_results_db, \
    checkmarx_scan_db, \
    checkmarx_scan_results_db, \
    gitlabsast_scan_db, \
    gitlabsast_scan_results_db, \
    gitlabsca_scan_db, \
    gitlabsca_scan_results_db, \
    gitlabcontainerscan_scan_db, \
    gitlabcontainerscan_scan_results_db
from networkscanners.models import scan_save_db, \
    nessus_scan_db, \
    ov_scan_result_db, \
    nessus_report_db
from compliance.models import inspec_scan_db, dockle_scan_db
from projects.models import project_db
from django.shortcuts import render,  HttpResponse, HttpResponseRedirect
from itertools import chain
import datetime
from webscanners.resources import AllResource
from notifications.models import Notification
from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User
from django.urls import reverse

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
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

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
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

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
    username = request.user.username
    all_project = project_db.objects.filter(username=username)
    if request.GET['project_id']:
        project_id = request.GET['project_id']
    else:
        project_id = ''

    all_zap_scan = zap_scans_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_burp_scan = burp_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_arachni_scan = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_netsparker_scan = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_webinspect_scan = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_acunetix_scan = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_dependency_scan = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_findbugs_scan = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_clair_scan = clair_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_trivy_scan = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_gitlabsast_scan = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_gitlabcontainerscan_scan = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_gitlabsca_scan = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_npmaudit_scan = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_nodejsscan_scan = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_semgrepscan_scan = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_tfsec_scan = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_whitesource_scan = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_checkmarx_scan = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_inspec_scan = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_dockle_scan = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_bandit_scan = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vuln'))

    all_openvas_scan = scan_save_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_nessus_scan = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('total_vul'))

    all_manual_scan = manual_scans_db.objects.filter(username=username, project_id=project_id). \
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

    for key, value in all_trivy_scan.items():
        if value is None:
            all_trivy = '0'
        else:
            all_trivy = value


    for key, value in all_gitlabsast_scan.items():
        if value is None:
            all_gitlabsast = '0'
        else:
            all_gitlabsast = value


    for key, value in all_gitlabcontainerscan_scan.items():
        if value is None:
            all_gitlabcontainerscan = '0'
        else:
            all_gitlabcontainerscan = value


    for key, value in all_gitlabsca_scan.items():
        if value is None:
            all_gitlabsca = '0'
        else:
            all_gitlabsca = value

    for key, value in all_npmaudit_scan.items():
        if value is None:
            all_npmaudit = '0'
        else:
            all_npmaudit = value

    for key, value in all_nodejsscan_scan.items():
        if value is None:
            all_nodejsscan = '0'
        else:
            all_nodejsscan = value

    for key, value in all_semgrepscan_scan.items():
        if value is None:
            all_semgrepscan = '0'
        else:
            all_semgrepscan = value

    for key, value in all_tfsec_scan.items():
        if value is None:
            all_tfsec = '0'
        else:
            all_tfsec = value

    for key, value in all_whitesource_scan.items():
        if value is None:
            all_whitesource = '0'
        else:
            all_whitesource = value

    for key, value in all_checkmarx_scan.items():
        if value is None:
            all_checkmarx = '0'
        else:
            all_checkmarx = value

    for key, value in all_inspec_scan.items():
        if value is None:
            all_inspec = '0'
        else:
            all_inspec = value

    for key, value in all_dockle_scan.items():
        if value is None:
            all_dockle = '0'
        else:
            all_dockle = value

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

    all_pentest_web = manual_scans_db.objects.filter(username=username, pentest_type='web', project_id=project_id). \
        aggregate(Sum('total_vul'))

    for key, value in all_pentest_web.items():
        if value is None:
            pentest_web = '0'
        else:
            pentest_web = value

    all_pentest_net = manual_scans_db.objects.filter(username=username, pentest_type='network', project_id=project_id). \
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
               int(all_trivy) + \
               int(all_gitlabsast) + \
               int(all_gitlabcontainerscan) + \
               int(all_gitlabsca) + \
               int(all_npmaudit) + \
               int(all_nodejsscan) + \
               int(all_semgrepscan) + \
               int(all_tfsec) + \
               int(all_whitesource) + \
               int(all_checkmarx) + \
               int(all_bandit) + \
               int(all_manual)

    total_network = int(all_openvas) + int(all_nessus) + int(pentest_net)

    total_web = int(all_zap) + int(all_burp) + int(pentest_web) + int(all_arachni) + \
                int(all_netsparker) + int(all_webinspect) + int(all_acunetix)

    total_compliance = int(all_inspec) + int(all_dockle)

    total_static = int(all_dependency) + int(all_findbugs) + int(all_bandit) + int(all_clair) + int(all_trivy) + int(
        all_npmaudit) + int(all_nodejsscan) + int(all_semgrepscan) + int(all_tfsec) + int(all_whitesource) + int(all_checkmarx) + int(all_gitlabsast) + int(all_gitlabcontainerscan) + int(all_gitlabsca)

    all_zap_high = zap_scans_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_arachni_high = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_netsparker_high = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_webinspect_high = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_acunetix_high = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_vul'))

    all_dependency_high = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_findbugs_high = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_clair_high = clair_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_trivy_high = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_gitlabsast_high = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_gitlabcontainerscan_high = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_gitlabsca_high = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_npmaudit_high = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_nodejsscan_high = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_semgrepscan_high = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_tfsec_high = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_whitesource_high = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_checkmarx_high = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_inspec_failed = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('inspec_failed'))

    all_dockle_failed = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('dockle_fatal'))

    all_bandit_high = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_HIGH'))

    all_nessus_high = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_total'))

    all_openvas_high = scan_save_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('high_total'))

    all_pentest_high = manual_scans_db.objects.filter(username=username, project_id=project_id). \
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

    for key, value in all_trivy_high.items():
        if value is None:
            high_trivy = '0'
        else:
            high_trivy = value

    for key, value in all_gitlabsast_high.items():
        if value is None:
            high_gitlabsast = '0'
        else:
            high_gitlabsast = value

    for key, value in all_gitlabcontainerscan_high.items():
        if value is None:
            high_gitlabcontainerscan = '0'
        else:
            high_gitlabcontainerscan = value

    for key, value in all_gitlabsca_high.items():
        if value is None:
            high_gitlabsca = '0'
        else:
            high_gitlabsca = value

    for key, value in all_npmaudit_high.items():
        if value is None:
            high_npmaudit = '0'
        else:
            high_npmaudit = value

    for key, value in all_nodejsscan_high.items():
        if value is None:
            high_nodejsscan = '0'
        else:
            high_nodejsscan = value


    for key, value in all_semgrepscan_high.items():
        if value is None:
            high_semgrepscan = '0'
        else:
            high_semgrepscan = value

    for key, value in all_tfsec_high.items():
        if value is None:
            high_tfsec = '0'
        else:
            high_tfsec = value

    for key, value in all_whitesource_high.items():
        if value is None:
            high_whitesource = '0'
        else:
            high_whitesource = value

    for key, value in all_checkmarx_high.items():
        if value is None:
            high_checkmarx = '0'
        else:
            high_checkmarx = value

    for key, value in all_inspec_failed.items():
        if value is None:
            failed_inspec = '0'
        else:
            failed_inspec = value

    for key, value in all_dockle_failed.items():
        if value is None:
            failed_dockle = '0'
        else:
            failed_dockle = value

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

    all_high_pentest_web = manual_scans_db.objects.filter(username=username, pentest_type='web', project_id=project_id). \
        aggregate(Sum('high_vul'))

    for key, value in all_high_pentest_web.items():
        if value is None:
            high_pentest_web = '0'
        else:
            high_pentest_web = value

    all_high_pentest_net = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                          project_id=project_id). \
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
               int(high_trivy) + \
               int(high_gitlabsast) + \
               int(high_gitlabcontainerscan) + \
               int(high_gitlabsca) + \
               int(high_npmaudit) + \
               int(high_nodejsscan) + \
               int(high_semgrepscan) + \
               int(high_tfsec) + \
               int(high_whitesource) + \
               int(high_checkmarx) + \
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
                      int(high_bandit) + \
                      int(high_trivy) + \
                      int(high_gitlabsast) + \
                      int(high_gitlabcontainerscan) + \
                      int(high_gitlabsca) + \
                      int(high_clair) + \
                      int(high_npmaudit) + \
                      int(high_nodejsscan) + \
                      int(high_semgrepscan) + \
                      int(high_tfsec) + \
                      int(high_whitesource) + \
                      int(high_checkmarx)

    all_network_high = int(openvas_high) + int(high_nessus) + int(high_pentest_net)

    all_compliance_failed = int(failed_inspec) + int(failed_dockle)

    all_zap_medium = zap_scans_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_arachni_medium = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_netsparker_medium = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_webinspect_medium = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_acunetix_medium = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_vul'))

    all_dependency_medium = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_findbugs_medium = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_clair_medium = clair_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_trivy_medium = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_gitlabsast_medium = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_gitlabcontainerscan_medium = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_gitlabsca_medium = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_npmaudit_medium = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_nodejsscan_medium = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_semgrepscan_medium = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_tfsec_medium = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_whitesource_medium = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_checkmarx_medium = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_inspec_passed = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('inspec_passed'))

    all_bandit_medium = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_MEDIUM'))

    all_nessus_medium = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_total'))

    all_openvas_medium = scan_save_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('medium_total'))
    all_pentest_medium = manual_scans_db.objects.filter(username=username, project_id=project_id). \
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

    for key, value in all_trivy_medium.items():
        if value is None:
            medium_trivy = '0'
        else:
            medium_trivy = value

    for key, value in all_gitlabsast_medium.items():
        if value is None:
            medium_gitlabsast = '0'
        else:
            medium_gitlabsast = value


    for key, value in all_gitlabcontainerscan_medium.items():
        if value is None:
            medium_gitlabcontainerscan = '0'
        else:
            medium_gitlabcontainerscan = value

    for key, value in all_gitlabsca_medium.items():
        if value is None:
            medium_gitlabsca = '0'
        else:
            medium_gitlabsca = value

    for key, value in all_npmaudit_medium.items():
        if value is None:
            medium_npmaudit = '0'
        else:
            medium_npmaudit = value

    for key, value in all_nodejsscan_medium.items():
        if value is None:
            medium_nodejsscan = '0'
        else:
            medium_nodejsscan = value

    for key, value in all_semgrepscan_medium.items():
        if value is None:
            medium_semgrepscan = '0'
        else:
            medium_semgrepscan = value

    for key, value in all_tfsec_medium.items():
        if value is None:
            medium_tfsec = '0'
        else:
            medium_tfsec = value

    for key, value in all_whitesource_medium.items():
        if value is None:
            medium_whitesource = '0'
        else:
            medium_whitesource = value

    for key, value in all_checkmarx_medium.items():
        if value is None:
            medium_checkmarx = '0'
        else:
            medium_checkmarx = value

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
                 int(medium_trivy) + \
                 int(medium_gitlabsast) + \
                 int(medium_gitlabcontainerscan) + \
                 int(medium_gitlabsca) + \
                 int(medium_npmaudit) + \
                 int(medium_nodejsscan) + \
                 int(medium_semgrepscan) + \
                 int(medium_tfsec) + \
                 int(medium_whitesource) + \
                 int(medium_checkmarx) + \
                 int(medium_bandit) + \
                 int(medium_nessus) + \
                 int(pentest_medium)

    all_medium_pentest_web = manual_scans_db.objects.filter(username=username, pentest_type='web',
                                                            project_id=project_id). \
        aggregate(Sum('medium_vul'))

    for key, value in all_medium_pentest_web.items():
        if value is None:
            medium_pentest_web = '0'
        else:
            medium_pentest_web = value

    all_medium_pentest_net = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                            project_id=project_id). \
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
                        int(medium_bandit) + \
                        int(medium_trivy) + \
                        int(medium_gitlabsast) + \
                        int(medium_gitlabcontainerscan) + \
                        int(medium_gitlabsca) + \
                        int(medium_clair) + \
                        int(medium_npmaudit) + \
                        int(medium_nodejsscan) + \
                        int(medium_semgrepscan) + \
                        int(medium_tfsec) + \
                        int(medium_whitesource) + \
                        int(medium_checkmarx)

    all_network_medium = int(openvas_medium) + int(medium_pentest_net) + int(medium_nessus)

    all_compliance_passed = int(passed_inspec)

    all_zap_low = zap_scans_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_arachni_low = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_netsparker_low = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_webinspect_low = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_acunetix_low = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_vul'))

    all_dependency_low = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_findbugs_low = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_clair_low = clair_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_trivy_low = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_gitlabsast_low = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_gitlabcontainerscan_low = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_gitlabsca_low = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_npmaudit_low = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_nodejsscan_low = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_semgrepscan_low = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_tfsec_low = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_whitesource_low = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_checkmarx_low = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_inspec_skipped = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('inspec_skipped'))

    all_dockle_skipped = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('dockle_info'))

    all_bandit_low = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('SEVERITY_LOW'))

    all_nessus_low = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_total'))

    all_openvas_low = scan_save_db.objects.filter(username=username, project_id=project_id). \
        aggregate(Sum('low_total'))

    all_pentest_low = manual_scans_db.objects.filter(username=username, project_id=project_id). \
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

    for key, value in all_trivy_low.items():
        if value is None:
            low_trivy = '0'
        else:
            low_trivy = value

    for key, value in all_gitlabsast_low.items():
        if value is None:
            low_gitlabsast = '0'
        else:
            low_gitlabsast = value

    for key, value in all_gitlabcontainerscan_low.items():
        if value is None:
            low_gitlabcontainerscan = '0'
        else:
            low_gitlabcontainerscan = value

    for key, value in all_gitlabsca_low.items():
        if value is None:
            low_gitlabsca = '0'
        else:
            low_gitlabsca = value

    for key, value in all_npmaudit_low.items():
        if value is None:
            low_npmaudit = '0'
        else:
            low_npmaudit = value

    for key, value in all_nodejsscan_low.items():
        if value is None:
            low_nodejsscan = '0'
        else:
            low_nodejsscan = value

    for key, value in all_semgrepscan_low.items():
        if value is None:
            low_semgrepscan = '0'
        else:
            low_semgrepscan = value

    for key, value in all_tfsec_low.items():
        if value is None:
            low_tfsec = '0'
        else:
            low_tfsec = value

    for key, value in all_whitesource_low.items():
        if value is None:
            low_whitesource = '0'
        else:
            low_whitesource = value

    for key, value in all_checkmarx_low.items():
        if value is None:
            low_checkmarx = '0'
        else:
            low_checkmarx = value

    for key, value in all_inspec_skipped.items():
        if value is None:
            skipped_inspec = '0'
        else:
            skipped_inspec = value

    for key, value in all_dockle_skipped.items():
        if value is None:
            skipped_dockle = '0'
        else:
            skipped_dockle = value

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
              int(low_trivy) + \
              int(low_gitlabsast) + \
              int(low_gitlabcontainerscan) + \
              int(low_gitlabsca) + \
              int(low_npmaudit) + \
              int(low_nodejsscan) + \
              int(low_semgrepscan) + \
              int(low_tfsec) + \
              int(low_whitesource) + \
              int(low_checkmarx) + \
              int(low_bandit) + \
              int(low_nessus) + \
              int(pentest_low)

    all_low_pentest_web = manual_scans_db.objects.filter(username=username, pentest_type='web', project_id=project_id). \
        aggregate(Sum('low_vul'))

    for key, value in all_low_pentest_web.items():
        if value is None:
            low_pentest_web = '0'
        else:
            low_pentest_web = value

    all_low_pentest_net = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                         project_id=project_id). \
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
                     int(low_bandit) + \
                     int(low_trivy) + \
                     int(low_gitlabsast) + \
                     int(low_gitlabcontainerscan) + \
                     int(low_gitlabsca) + \
                     int(low_clair) + \
                     int(low_npmaudit) + \
                     int(low_nodejsscan) + \
                     int(low_semgrepscan) + \
                     int(low_tfsec) + \
                     int(low_whitesource) + \
                     int(low_checkmarx)

    all_network_low = int(openvas_low) + int(low_nessus) + int(low_pentest_net)

    all_compliance_skipped = int(skipped_inspec) + int(skipped_dockle)

    project_dat = project_db.objects.filter(username=username, project_id=project_id)
    burp = burp_scan_db.objects.filter(username=username, project_id=project_id)
    zap = zap_scans_db.objects.filter(username=username, project_id=project_id)
    arachni = arachni_scan_db.objects.filter(username=username, project_id=project_id)
    webinspect = webinspect_scan_db.objects.filter(username=username, project_id=project_id)
    netsparker = netsparker_scan_db.objects.filter(username=username, project_id=project_id)
    acunetix = acunetix_scan_db.objects.filter(username=username, project_id=project_id)

    dependency_check = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id)
    findbugs = findbugs_scan_db.objects.filter(username=username, project_id=project_id)
    clair = clair_scan_db.objects.filter(username=username, project_id=project_id)
    trivy = trivy_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabsast = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabcontainerscan = gitlabcontainerscan_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabsca = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id)
    npmaudit = npmaudit_scan_db.objects.filter(username=username, project_id=project_id)
    nodejsscan = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id)
    semgrepscan = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id)
    tfsec = tfsec_scan_db.objects.filter(username=username, project_id=project_id)
    whitesource = whitesource_scan_db.objects.filter(username=username, project_id=project_id)
    checkmarx = checkmarx_scan_db.objects.filter(username=username, project_id=project_id)
    bandit = bandit_scan_db.objects.filter(username=username, project_id=project_id)

    web_scan_dat = chain(burp, zap, arachni, webinspect, netsparker, acunetix)
    static_scan = chain(dependency_check, findbugs, clair, trivy, gitlabsast, gitlabcontainerscan, gitlabsca, npmaudit, nodejsscan, semgrepscan, tfsec, whitesource, checkmarx, bandit)
    openvas_dat = scan_save_db.objects.filter(username=username, project_id=project_id)
    nessus_dat = nessus_scan_db.objects.filter(username=username, project_id=project_id)

    network_dat = chain(openvas_dat, nessus_dat)

    inspec_dat = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    dockle_dat = dockle_scan_db.objects.filter(username=username, project_id=project_id)

    compliance_dat = chain(inspec_dat, dockle_dat)

    all_comp_inspec = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_comp_dockle = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    all_compliance = chain(all_comp_inspec, all_comp_dockle)

    pentest = manual_scans_db.objects.filter(username=username, project_id=project_id)

    zap_false_positive = zap_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                            project_id=project_id)
    burp_false_positive = burp_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                             project_id=project_id)
    arachni_false_positive = arachni_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                                   project_id=project_id)
    netsparker_false_positive = netsparker_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                                         project_id=project_id)
    webinspect_false_positive = webinspect_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                                         project_id=project_id)
    acunetix_false_positive = acunetix_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                                     project_id=project_id)

    dependencycheck_false_positive = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                    false_positive='Yes',
                                                                                    project_id=project_id)
    findbugs_false_positive = findbugs_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                      project_id=project_id)
    clair_false_positive = clair_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
    trivy_false_positive = trivy_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
    gitlabsast_false_positive = gitlabsast_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
    gitlabcontainerscan_false_positive = gitlabcontainerscan_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                          project_id=project_id)
    gitlabsca_false_positive = gitlabsca_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
    npmaudit_false_positive = npmaudit_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                      project_id=project_id)
    nodejsscan_false_positive = nodejsscan_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                          project_id=project_id)
    semgrepscan_false_positive = semgrepscan_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                          project_id=project_id)
    tfsec_false_positive = tfsec_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
    whitesource_false_positive = whitesource_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                            project_id=project_id)
    checkmarx_false_positive = checkmarx_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                            project_id=project_id)
    bandit_false_positive = bandit_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                  project_id=project_id)

    openvas_false_positive = ov_scan_result_db.objects.filter(username=username, false_positive='Yes',
                                                              project_id=project_id)
    nessus_false_positive = nessus_report_db.objects.filter(username=username, false_positive='Yes',
                                                            project_id=project_id)

    zap_closed_vuln = zap_scan_results_db.objects.filter(username=username, vuln_status='Closed', project_id=project_id)
    burp_closed_vuln = burp_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                          project_id=project_id)
    arachni_closed_vuln = arachni_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                                project_id=project_id)
    netsparker_closed_vuln = netsparker_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                                      project_id=project_id)
    webinspect_closed_vuln = webinspect_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                                      project_id=project_id)
    acunetix_closed_vuln = acunetix_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                                  project_id=project_id)
    openvas_closed_vuln = ov_scan_result_db.objects.filter(username=username, vuln_status='Closed',
                                                           project_id=project_id)
    nessus_closed_vuln = nessus_report_db.objects.filter(username=username, vuln_status='Closed', project_id=project_id)

    dependencycheck_closed_vuln = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                 vuln_status='Closed',
                                                                                 project_id=project_id)
    findbugs_closed_vuln = findbugs_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                   project_id=project_id)
    clair_closed_vuln = clair_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id)
    trivy_closed_vuln = trivy_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id)
    gitlabsast_closed_vuln = gitlabsast_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id)
    gitlabcontainerscan_closed_vuln = gitlabcontainerscan_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                       project_id=project_id)
    gitlabsca_closed_vuln = gitlabsca_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id)
    npmaudit_closed_vuln = npmaudit_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                   project_id=project_id)
    nodejsscan_closed_vuln = nodejsscan_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                       project_id=project_id)
    semgrepscan_closed_vuln = semgrepscan_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                       project_id=project_id)
    tfsec_closed_vuln = tfsec_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id)
    whitesource_closed_vuln = whitesource_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                         project_id=project_id)

    checkmarx_closed_vuln = checkmarx_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                         project_id=project_id)

    bandit_closed_vuln = bandit_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                               project_id=project_id)

    all_closed_vuln = int(len(zap_closed_vuln)) + \
                      int(len(burp_closed_vuln)) + \
                      int(len(arachni_closed_vuln)) + \
                      int(len(acunetix_closed_vuln)) + \
                      int(len(netsparker_closed_vuln)) + \
                      int(len(webinspect_closed_vuln)) + \
                      int(len(openvas_closed_vuln)) + \
                      int(len(nessus_closed_vuln)) + \
                      int(len(dependencycheck_closed_vuln)) + \
                      int(len(findbugs_closed_vuln)) + \
                      int(len(clair_closed_vuln)) + \
                      int(len(trivy_closed_vuln)) + \
                      int(len(gitlabsast_closed_vuln)) + \
                      int(len(gitlabcontainerscan_closed_vuln)) + \
                      int(len(gitlabsca_closed_vuln)) + \
                      int(len(npmaudit_closed_vuln)) + \
                      int(len(nodejsscan_closed_vuln)) + \
                      int(len(semgrepscan_closed_vuln)) + \
                      int(len(tfsec_closed_vuln)) + \
                      int(len(whitesource_closed_vuln)) + \
                      int(len(checkmarx_closed_vuln)) + \
                      int(len(bandit_closed_vuln))

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
                         int(len(clair_false_positive)) + \
                         int(len(trivy_false_positive)) + \
                         int(len(gitlabsast_false_positive)) + \
                         int(len(gitlabcontainerscan_false_positive)) + \
                         int(len(gitlabsca_false_positive)) + \
                         int(len(npmaudit_false_positive)) + \
                         int(len(nodejsscan_false_positive)) + \
                         int(len(semgrepscan_false_positive)) + \
                         int(len(tfsec_false_positive)) + \
                         int(len(whitesource_false_positive)) + \
                         int(len(checkmarx_false_positive)) + \
                         int(len(bandit_false_positive))

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
                   'trivy': trivy,
                   'gitlabsast': gitlabsast,
                   'gitlabcontainerscan': gitlabcontainerscan,
                   'gitlabsca': gitlabsca,
                   'npmaudit': npmaudit,
                   'nodejsscan': nodejsscan,
                   'semgrepscan': semgrepscan,
                   'tfsec': tfsec,
                   'whitesource': whitesource,
                   'checkmarx': checkmarx,
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
                   'all_trivy_scan': all_trivy_scan,
                   'all_gitlabsast_scan': all_gitlabsast_scan,
                   'all_gitlabcontainerscan_scan': all_gitlabcontainerscan_scan,
                   'all_gitlabsca_scan': all_gitlabsca_scan,
                   'all_npmaudit_scan': all_npmaudit_scan,
                   'all_nodejsscan_scan': all_nodejsscan_scan,
                   'all_semgrepscan_scan': all_semgrepscan_scan,
                   'all_tfsec_scan': all_tfsec_scan,
                   'all_whitesource_scan': all_whitesource_scan,
                   'all_checkmarx_scan': all_checkmarx_scan,
                   'all_webinspect_scan': all_webinspect_scan,

                   'all_compliance_failed': all_compliance_failed,
                   'all_compliance_passed': all_compliance_passed,
                   'all_compliance_skipped': all_compliance_skipped,
                   'total_compliance': total_compliance,

                   'openvas_dat': openvas_dat,
                   'nessus_dat': nessus_dat,

                   'all_compliance': all_compliance,

                   'compliance_dat': compliance_dat,
                   'inspec_dat': inspec_dat,
                   'dockle_dat': dockle_dat,

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

                   'all_trivy_high': all_trivy_high,
                   'all_trivy_low': all_trivy_low,
                   'all_trivy_medium': all_trivy_medium,

                   'all_gitlabsast_high': all_gitlabsast_high,
                   'all_gitlabsast_low': all_gitlabsast_low,
                   'all_gitlabsast_medium': all_gitlabsast_medium,

                   'all_gitlabcontainerscan_high': all_gitlabcontainerscan_high,
                   'all_gitlabcontainerscan_low': all_gitlabcontainerscan_low,
                   'all_gitlabcontainerscan_medium': all_gitlabcontainerscan_medium,

                   'all_gitlabsca_high': all_gitlabsca_high,
                   'all_gitlabsca_low': all_gitlabsca_low,
                   'all_gitlabsca_medium': all_gitlabsca_medium,

                   'all_npmaudit_high': all_npmaudit_high,
                   'all_npmaudit_low': all_npmaudit_low,
                   'all_npmaudit_medium': all_npmaudit_medium,

                   'all_nodejsscan_high': all_nodejsscan_high,
                   'all_nodejsscan_low': all_nodejsscan_low,
                   'all_nodejsscan_medium': all_nodejsscan_medium,

                   'all_semgrepscan_high': all_semgrepscan_high,
                   'all_semgrepscan_low': all_semgrepscan_low,
                   'all_semgrepscan_medium': all_semgrepscan_medium,

                   'all_tfsec_high': all_tfsec_high,
                   'all_tfsec_low': all_tfsec_low,
                   'all_tfsec_medium': all_tfsec_medium,

                   'all_whitesource_high': all_whitesource_high,
                   'all_whitesource_low': all_whitesource_low,
                   'all_whitesource_medium': all_whitesource_medium,

                   'all_checkmarx_high': all_checkmarx_high,
                   'all_checkmarx_low': all_checkmarx_low,
                   'all_checkmarx_medium': all_checkmarx_medium,

                   'all_closed_vuln': all_closed_vuln,
                   'all_false_positive': all_false_positive,
                   'message': all_notify
                   })


def all_high_vuln(request):
    username = request.user.username
    all_notify = Notification.objects.unread()
    if request.GET['project_id']:
        project_id = request.GET['project_id']
        severity = request.GET['severity']
    else:
        project_id = ''
        severity = ''

    if severity == 'High':

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='High',
                                                          false_positive='No')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='High',
                                                                 false_positive='No')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Critical', 'High'],
                                                                       false_positive='No')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='High',
                                                                       false_positive='No')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='High',
                                                                   false_positive='No')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='High',
                                                           false_positive='No')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='High',
                                                                                  false_positive='No')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='High',
                                                                    project_id=project_id,
                                                                    false_positive='No')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='HIGH',
                                                                project_id=project_id,
                                                                false_positive='No')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='High',
                                                                        project_id=project_id,
                                                                        false_positive='No')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='High', project_id=project_id,
                                                              false_positive='No')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='High',
                                                                    project_id=project_id,
                                                                    false_positive='No')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='High',
                                                                        project_id=project_id,
                                                                        false_positive='No')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='High',
                                                                        project_id=project_id,
                                                                        false_positive='No')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='High', project_id=project_id,
                                                              false_positive='No')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='High',
                                                                          project_id=project_id,
                                                                          false_positive='No')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='High',
                                                                          project_id=project_id,
                                                                          false_positive='No')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='High', project_id=project_id,
                                                            false_positive='No')
        nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='High', project_id=project_id,
                                                          false_positive='No')

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='High',
                                                                 project_id=project_id)

    elif severity == 'Medium':

        # All Medium

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='Medium')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='Medium')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Medium'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='Medium')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='Medium')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='Medium')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='Medium')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Medium',
                                                                    project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='MEDIUM',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                        project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                              project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                    project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                        project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                        project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Medium',
                                                              project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                          project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                          project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Medium', project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='Medium',
                                                          project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                 project_id=project_id)

    # All Low
    elif severity == 'Low':

        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          risk='Low')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 severity='Low')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity__in=[
                                                                           'Low'])
        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       severity='Low')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   VulnSeverity='Low')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           severity='Low')
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  severity='Low')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Low',
                                                                    project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='LOW',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Low', project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Low', project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Low', project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                        project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Low', project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Low',
                                                                    project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Low',
                                                                        project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Low',
                                                                        project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Low', project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Low',
                                                                          project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Low',
                                                                          project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Low', project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='Low', project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Low',
                                                                 project_id=project_id)

    elif severity == 'Total':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          )
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 )
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       )

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       )
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   )
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id)
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id)

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id)

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id)
        nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, project_id=project_id)

    elif severity == 'False':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          false_positive='Yes')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 false_positive='Yes')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       false_positive='Yes')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       false_positive='Yes')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   false_positive='Yes')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           false_positive='Yes')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  false_positive='Yes')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    false_positive='Yes')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    false_positive='Yes')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          false_positive='Yes')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          false_positive='Yes')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                            false_positive='Yes')
        nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id,
                                                          false_positive='Yes')

        pentest_all_high = ''

    elif severity == 'Close':
        zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                          vuln_status='Closed')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 vuln_status='Closed')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Closed')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Closed')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   vuln_status='Closed')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           vuln_status='Closed')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  vuln_status='Closed')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Closed')
        bandit_all_high = bandit_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                project_id=project_id)
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Closed')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Closed')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Closed')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                            vuln_status='Closed')
        nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id,
                                                          vuln_status='Closed')

        pentest_all_high = ''

    else:
        return HttpResponseRedirect(reverse('dashboard:proj_data' + '?project_id=%s' % project_id))

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
                   'trivy_all_high': trivy_all_high,
                   'gitlabsast_all_high': gitlabsast_all_high,
                   'gitlabcontainerscan_all_high': gitlabcontainerscan_all_high,
                   'gitlabsca_all_high': gitlabsca_all_high,
                   'npmaudit_all_high': npmaudit_all_high,
                   'nodejsscan_all_high': nodejsscan_all_high,
                   'semgrepscan_all_high': semgrepscan_all_high,
                   'tfsec_all_high': tfsec_all_high,
                   'whitesource_all_high': whitesource_all_high,
                   'checkmarx_all_high': checkmarx_all_high,
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
    username = request.user.username
    dataset = None
    pentest_all_high = None

    if request.method == 'POST':
        project_id = request.POST.get("project_id")
        report_type = request.POST.get("type")
        severity = request.POST.get("severity")

        resource = AllResource()

        if severity == 'High':

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              risk='High')
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     severity='high')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity__in=[
                                                                               'Critical', 'High'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity='High')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       VulnSeverity='High')
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               severity='High')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      severity='High')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='High',
                                                                        project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='High',
                                                                    project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='High',
                                                                  project_id=project_id)

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='HIGH',
                                                                  project_id=project_id)

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='HIGH',
                                                                  project_id=project_id)

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='HIGH',
                                                                  project_id=project_id)

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='HIGH',
                                                                            project_id=project_id)

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                        project_id=project_id)

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                            project_id=project_id)

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                            project_id=project_id)

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                  project_id=project_id)

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                              project_id=project_id)

            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='HIGH',
                                                                              project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='High', project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='High',
                                                              project_id=project_id)

            pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='High',
                                                                     project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             pentest_all_high,
                             bandit_all_high
                             )

        elif severity == 'Medium':
            # All Medium

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              risk='Medium')
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     severity='Medium')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity__in=[
                                                                               'Medium'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity='Medium')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       VulnSeverity='Medium')
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               severity='Medium')
            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      severity='Medium')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Medium',
                                                                        project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='Medium',
                                                                    project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                  project_id=project_id)

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                  project_id=project_id)

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                  project_id=project_id)

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                  project_id=project_id)

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                            project_id=project_id)

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                        project_id=project_id)

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                            project_id=project_id)

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                            project_id=project_id)

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                  project_id=project_id)

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                              project_id=project_id)

            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                              project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Medium',
                                                                project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='Medium',
                                                              project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(username=username, severity='Medium',
                                                             project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

            # dataset = resource.export(all_data)

        elif severity == 'Low':

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              risk='Low')
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     severity='Low')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity__in=[
                                                                               'Low'])
            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           severity='Low')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       VulnSeverity='Low')
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               severity='Low')
            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      severity='Low')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, risk='Low',
                                                                        project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(username=username, issue_severity='Low',
                                                                    project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                  project_id=project_id)

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                  project_id=project_id)

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                  project_id=project_id)

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                  project_id=project_id)

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                            project_id=project_id)

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, severity='Low',
                                                                        project_id=project_id)

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, severity='Low',
                                                                            project_id=project_id)

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, severity='Low',
                                                                            project_id=project_id)

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, severity='Low',
                                                                  project_id=project_id)

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, severity='Low',
                                                                              project_id=project_id)
            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, severity='Low',
                                                                              project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, threat='Low', project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(username=username, risk_factor='Low',
                                                              project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(username=username, severity='Low', project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

            # dataset = resource.export(all_data)

        elif severity == 'Total':

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              )
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     )
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           )

            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           )
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       )
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               )

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      )
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id)
            bandit_all_high = bandit_scan_results_db.objects.filter(username=username, project_id=project_id)
            clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id)

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id)

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id)

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id)

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id)

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id)

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id)

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id)

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id)

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id)
            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id)

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id)
            nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id)

            pentest_all_high = manual_scan_results_db.filter(username=username, project_id=project_id)

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high,
                             bandit_all_high,
                             pentest_all_high
                             )

        elif severity == 'False':

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     false_positive='Yes')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           false_positive='Yes')

            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           false_positive='Yes')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       false_positive='Yes')
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               false_positive='Yes')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      false_positive='Yes')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')
            clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  false_positive='Yes')

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  false_positive='Yes')

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  false_positive='Yes')

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  false_positive='Yes')

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            false_positive='Yes')

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            false_positive='Yes')

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            false_positive='Yes')

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  false_positive='Yes')

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                              false_positive='Yes')

            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                              false_positive='Yes')

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                false_positive='Yes')
            nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id,
                                                              false_positive='Yes')

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high
                             )

        elif severity == 'Close':

            zap_all_high = zap_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')
            arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                     vuln_status='Closed')
            webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           vuln_status='Closed')

            netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                           vuln_status='Closed')
            acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Closed')
            burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                               vuln_status='Closed')

            dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                      project_id=project_id,
                                                                                      vuln_status='Closed')
            findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')
            clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  vuln_status='Closed')

            trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  vuln_status='Closed')

            gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  vuln_status='Closed')

            gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  vuln_status='Closed')

            gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            vuln_status='Closed')

            npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

            nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            vuln_status='Closed')

            semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                            vuln_status='Closed')

            tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                  vuln_status='Closed')

            whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                              vuln_status='Closed')

            checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                              vuln_status='Closed')

            openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                vuln_status='Closed')
            nessus_all_high = nessus_report_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Closed')

            all_data = chain(zap_all_high,
                             burp_all_high,
                             arachni_all_high,
                             webinspect_all_high,
                             netsparker_all_high,
                             acunetix_all_high,
                             dependencycheck_all_high,
                             findbugs_all_high,
                             clair_all_high,
                             trivy_all_high,
                             gitlabsast_all_high,
                             gitlabcontainerscan_all_high,
                             gitlabsca_all_high,
                             npmaudit_all_high,
                             nodejsscan_all_high,
                             semgrepscan_all_high,
                             tfsec_all_high,
                             whitesource_all_high,
                             checkmarx_all_high,
                             openvas_all_high,
                             netsparker_all_high,
                             nessus_all_high
                             )

        else:
            return HttpResponseRedirect(reverse('dashboard:proj_data' + '?project_id=%s' % project_id))

        dataset = resource.export(all_data)

        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % project_id
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % project_id
            return response
