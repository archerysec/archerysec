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

# import your web scanners db <scannername>
from webscanners.models import WebScansDb, \
    burp_scan_db, \
    arachni_scan_db, \
    netsparker_scan_db, \
    webinspect_scan_db, \
    WebScanResultsDb, \
    burp_scan_result_db, \
    arachni_scan_result_db, \
    netsparker_scan_result_db, \
    webinspect_scan_result_db, \
    acunetix_scan_db, acunetix_scan_result_db

# import pentest database db <scannername>
from manual_scan.models import manual_scans_db, manual_scan_results_db

# import static scanners database model db <scannername>
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
    twistlock_scan_db, \
    twistlock_scan_results_db, \
    gitlabsca_scan_db, \
    gitlabsca_scan_results_db, \
    gitlabcontainerscan_scan_db, \
    gitlabcontainerscan_scan_results_db, \
    brakeman_scan_db, \
    brakeman_scan_results_db

from networkscanners.models import openvas_scan_db, \
    nessus_scan_db, \
    ov_scan_result_db, \
    nessus_scan_results_db
from compliance.models import inspec_scan_db, dockle_scan_db
from itertools import chain
# Create your views here.
chart = []
all_high_stat = ""
data = ""


# Add your scanner funciton to query data 

"""
ex.

def all_<scannername>(username, project_id, query):
    all_<scannername> = None
    if query == 'total':
        all_<scannername>_scan = <scannername>_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_<scannername>_scan.items():
            if value is None:
                all_<scannername> = '0'
            else:
                all_<scannername> = value

    elif query == 'high':

        all_<scannername>_high = <scannername>_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_<scannername>_high.items():
            if value is None:
                all_<scannername> = '0'
            else:
                all_<scannername> = value

    elif query == 'medium':
        all_<scannername>_medium = <scannername>_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_<scannername>_medium.items():
            if value is None:
                all_<scannername> = '0'
            else:
                all_<scannername> = value

    elif query == 'low':
        all_<scannername>_low = <scannername>_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_<scannername>_low.items():
            if value is None:
                all_<scannername> = '0'
            else:
                all_<scannername> = value

    return all_<scannername>

"""

def all_brakeman(username, project_id, query):
    all_brakeman = None
    if query == 'total':
        all_brakeman_scan = brakeman_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))
 
        for key, value in all_brakeman_scan.items():
            if value is None:
                all_brakeman = '0'
            else:
                all_brakeman = value
 
    elif query == 'high':
 
        all_brakeman_high = brakeman_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))
 
        for key, value in all_brakeman_high.items():
            if value is None:
                all_brakeman = '0'
            else:
                all_brakeman = value
 
    elif query == 'medium':
        all_brakeman_medium = brakeman_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))
 
        for key, value in all_brakeman_medium.items():
            if value is None:
                all_brakeman = '0'
            else:
                all_brakeman = value
 
    elif query == 'low':
        all_brakeman_low = brakeman_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))
 
        for key, value in all_brakeman_low.items():
            if value is None:
                all_brakeman = '0'
            else:
                all_brakeman = value
 
    return all_brakeman


def all_zap(username, project_id, query):
    all_zap = None

    if query == 'total':
        all_zap_scan = WebScansDb.objects.filter(username=username, project_id=project_id, scanner='zap'). \
            aggregate(Sum('total_vul'))

        for key, value in all_zap_scan.items():
            if value is None:
                all_zap = '0'
            else:
                all_zap = value

    elif query == 'high':
        all_zap_high = WebScansDb.objects.filter(username=username, project_id=project_id, scanner='zap'). \
            aggregate(Sum('high_vul'))

        for key, value in all_zap_high.items():
            if value is None:
                all_zap = '0'
            else:
                all_zap = value

        def all_zap_scan():
            WebScansDb.objects.filter(username=username, project_id=project_id, scanner='zap'). \
                aggregate(Sum('high_vul'))
            return all_zap_scan

    elif query == 'medium':
        all_zap_medium = WebScansDb.objects.filter(username=username, project_id=project_id, scanner='zap'). \
            aggregate(Sum('medium_vul'))

        for key, value in all_zap_medium.items():
            if value is None:
                all_zap = '0'
            else:
                all_zap = value

    elif query == 'low':
        all_zap_low = WebScansDb.objects.filter(username=username, project_id=project_id, scanner='zap'). \
            aggregate(Sum('low_vul'))

        for key, value in all_zap_low.items():
            if value is None:
                all_zap = '0'
            else:
                all_zap = value

    return all_zap


def all_burp(username, project_id, query):
    all_burp = None

    if query == 'total':
        all_burp_scan = burp_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_burp_scan.items():
            if value is None:
                all_burp = '0'
            else:
                all_burp = value

    elif query == 'high':
        all_burp_high = burp_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_burp_high.items():
            if value is None:
                all_burp = '0'
            else:
                all_burp = value

    elif query == 'medium':
        all_burp_medium = burp_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_burp_medium.items():
            if value is None:
                all_burp = '0'
            else:
                all_burp = value

    elif query == 'low':
        all_burp_low = burp_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_burp_low.items():
            if value is None:
                all_burp = '0'
            else:
                all_burp = value

    return all_burp


def all_arachni(username, project_id, query):
    all_arachni = None
    if query == 'total':
        all_arachni_scan = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_arachni_scan.items():
            if value is None:
                all_arachni = '0'
            else:
                all_arachni = value

    elif query == 'high':
        all_arachni_high = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_arachni_high.items():
            if value is None:
                all_arachni = '0'
            else:
                all_arachni = value

    elif query == 'medium':
        all_arachni_medium = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_arachni_medium.items():
            if value is None:
                all_arachni = '0'
            else:
                all_arachni = value

    elif query == 'low':
        all_arachni_low = arachni_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_arachni_low.items():
            if value is None:
                all_arachni = '0'
            else:
                all_arachni = value

    return all_arachni


def all_netsparker(username, project_id, query):
    all_netsparker = None
    if query == 'total':
        all_netsparker_scan = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_netsparker_scan.items():
            if value is None:
                all_netsparker = '0'
            else:
                all_netsparker = value

    elif query == 'high':
        all_netsparker_high = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_netsparker_high.items():
            if value is None:
                all_netsparker = '0'
            else:
                all_netsparker = value

    elif query == 'medium':
        all_netsparker_medium = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_netsparker_medium.items():
            if value is None:
                all_netsparker = '0'
            else:
                all_netsparker = value

    elif query == 'low':
        all_netsparker_low = netsparker_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_netsparker_low.items():
            if value is None:
                all_netsparker = '0'
            else:
                all_netsparker = value

    return all_netsparker


def all_webinspect(username, project_id, query):
    all_webinspect = None
    if query == 'total':
        all_webinspect_scan = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_webinspect_scan.items():
            if value is None:
                all_webinspect = '0'
            else:
                all_webinspect = value

    elif query == 'high':
        all_webinspect_high = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_webinspect_high.items():
            if value is None:
                all_webinspect = '0'
            else:
                all_webinspect = value

    elif query == 'medium':
        all_webinspect_medium = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_webinspect_medium.items():
            if value is None:
                all_webinspect = '0'
            else:
                all_webinspect = value

    elif query == 'low':
        all_webinspect_low = webinspect_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_webinspect_low.items():
            if value is None:
                all_webinspect = '0'
            else:
                all_webinspect = value

    return all_webinspect


def all_acunetix(username, project_id, query):
    all_acunetix = None
    if query == 'total':
        all_acunetix_scan = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_acunetix_scan.items():
            if value is None:
                all_acunetix = '0'
            else:
                all_acunetix = value

    elif query == 'high':
        all_acunetix_high = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_acunetix_high.items():
            if value is None:
                all_acunetix = '0'
            else:
                all_acunetix = value

    elif query == 'medium':
        all_acunetix_medium = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_acunetix_medium.items():
            if value is None:
                all_acunetix = '0'
            else:
                all_acunetix = value

    elif query == 'low':
        all_acunetix_low = acunetix_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_acunetix_low.items():
            if value is None:
                all_acunetix = '0'
            else:
                all_acunetix = value

    return all_acunetix


def all_dependency(username, project_id, query):
    all_dependency = None
    if query == 'total':
        all_dependency_scan = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_dependency_scan.items():
            if value is None:
                all_dependency = '0'
            else:
                all_dependency = value

    elif query == 'high':

        all_dependency_high = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_dependency_high.items():
            if value is None:
                all_dependency = '0'
            else:
                all_dependency = value

    elif query == 'medium':
        all_dependency_medium = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_dependency_medium.items():
            if value is None:
                all_dependency = '0'
            else:
                all_dependency = value

    elif query == 'low':
        all_dependency_low = dependencycheck_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_dependency_low.items():
            if value is None:
                all_dependency = '0'
            else:
                all_dependency = value

    return all_dependency


def all_findbugs(username, project_id, query):
    all_findbugs = None
    if query == 'total':
        all_findbugs_scan = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_findbugs_scan.items():
            if value is None:
                all_findbugs = '0'
            else:
                all_findbugs = value

    elif query == 'high':

        all_findbugs_high = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_findbugs_high.items():
            if value is None:
                all_findbugs = '0'
            else:
                all_findbugs = value

    elif query == 'medium':
        all_findbugs_medium = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_findbugs_medium.items():
            if value is None:
                all_findbugs = '0'
            else:
                all_findbugs = value

    elif query == 'low':
        all_findbugs_low = findbugs_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_findbugs_low.items():
            if value is None:
                all_findbugs = '0'
            else:
                all_findbugs = value

    return all_findbugs


def all_clair(username, project_id, query):
    all_clair = None
    if query == 'total':
        all_clair_scan = clair_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_clair_scan.items():
            if value is None:
                all_clair = '0'
            else:
                all_clair = value

    elif query == 'high':

        all_clair_high = clair_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_clair_high.items():
            if value is None:
                all_clair = '0'
            else:
                all_clair = value

    elif query == 'medium':
        all_clair_medium = clair_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_clair_medium.items():
            if value is None:
                all_clair = '0'
            else:
                all_clair = value

    elif query == 'low':
        all_clair_low = clair_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_clair_low.items():
            if value is None:
                all_clair = '0'
            else:
                all_clair = value

    return all_clair


def all_trivy(username, project_id, query):
    all_trivy = None
    if query == 'total':
        all_trivy_scan = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_trivy_scan.items():
            if value is None:
                all_trivy = '0'
            else:
                all_trivy = value

    elif query == 'high':

        all_trivy_high = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_trivy_high.items():
            if value is None:
                all_trivy = '0'
            else:
                all_trivy = value

    elif query == 'medium':
        all_trivy_medium = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_trivy_medium.items():
            if value is None:
                all_trivy = '0'
            else:
                all_trivy = value

    elif query == 'low':
        all_trivy_low = trivy_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_trivy_low.items():
            if value is None:
                all_trivy = '0'
            else:
                all_trivy = value

    return all_trivy


def all_gitlabsast(username, project_id, query):
    all_gitlabsast = None
    if query == 'total':
        all_gitlabsast_scan = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_gitlabsast_scan.items():
            if value is None:
                all_gitlabsast = '0'
            else:
                all_gitlabsast = value

    elif query == 'high':

        all_gitlabsast_high = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_gitlabsast_high.items():
            if value is None:
                all_gitlabsast = '0'
            else:
                all_gitlabsast = value

    elif query == 'medium':
        all_gitlabsast_medium = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_gitlabsast_medium.items():
            if value is None:
                all_gitlabsast = '0'
            else:
                all_gitlabsast = value

    elif query == 'low':
        all_gitlabsast_low = gitlabsast_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_gitlabsast_low.items():
            if value is None:
                all_gitlabsast = '0'
            else:
                all_gitlabsast = value

    return all_gitlabsast

def all_twistlock(username, project_id, query):
    all_twistlock = None
    if query == 'total':
        all_twistlock_scan = twistlock_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_twistlock_scan.items():
            if value is None:
                all_twistlock = '0'
            else:
                all_twistlock = value

    elif query == 'high':

        all_twistlock_high = twistlock_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_twistlock_high.items():
            if value is None:
                all_twistlock = '0'
            else:
                all_twistlock = value

    elif query == 'medium':
        all_twistlock_medium = twistlock_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_twistlock_medium.items():
            if value is None:
                all_twistlock = '0'
            else:
                all_twistlock = value

    elif query == 'low':
        all_twistlock_low = twistlock_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_twistlock_low.items():
            if value is None:
                all_twistlock = '0'
            else:
                all_twistlock = value

    return all_twistlock

def all_gitlabcontainerscan(username, project_id, query):
    all_gitlabcontainerscan = None
    if query == 'total':
        all_gitlabcontainerscan_scan = gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                  project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_gitlabcontainerscan_scan.items():
            if value is None:
                all_gitlabcontainerscan = '0'
            else:
                all_gitlabcontainerscan = value

    elif query == 'high':

        all_gitlabcontainerscan_high = gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                  project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_gitlabcontainerscan_high.items():
            if value is None:
                all_gitlabcontainerscan = '0'
            else:
                all_gitlabcontainerscan = value

    elif query == 'medium':
        all_gitlabcontainerscan_medium = gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                    project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_gitlabcontainerscan_medium.items():
            if value is None:
                all_gitlabcontainerscan = '0'
            else:
                all_gitlabcontainerscan = value

    elif query == 'low':
        all_gitlabcontainerscan_low = gitlabcontainerscan_scan_db.objects.filter(username=username,
                                                                                 project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_gitlabcontainerscan_low.items():
            if value is None:
                all_gitlabcontainerscan = '0'
            else:
                all_gitlabcontainerscan = value

    return all_gitlabcontainerscan


def all_gitlabsca(username, project_id, query):
    all_gitlabsca = None
    if query == 'total':
        all_gitlabsca_scan = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_gitlabsca_scan.items():
            if value is None:
                all_gitlabsca = '0'
            else:
                all_gitlabsca = value

    elif query == 'high':

        all_gitlabsca_high = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_gitlabsca_high.items():
            if value is None:
                all_gitlabsca = '0'
            else:
                all_gitlabsca = value

    elif query == 'medium':
        all_gitlabsca_medium = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_gitlabsca_medium.items():
            if value is None:
                all_gitlabsca = '0'
            else:
                all_gitlabsca = value

    elif query == 'low':
        all_gitlabsca_low = gitlabsca_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_gitlabsca_low.items():
            if value is None:
                all_gitlabsca = '0'
            else:
                all_gitlabsca = value

    return all_gitlabsca


def all_npmaudit(username, project_id, query):
    all_npmaudit = None
    if query == 'total':
        all_npmaudit_scan = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_npmaudit_scan.items():
            if value is None:
                all_npmaudit = '0'
            else:
                all_npmaudit = value

    elif query == 'high':

        all_npmaudit_high = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_npmaudit_high.items():
            if value is None:
                all_npmaudit = '0'
            else:
                all_npmaudit = value

    elif query == 'medium':
        all_npmaudit_medium = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_npmaudit_medium.items():
            if value is None:
                all_npmaudit = '0'
            else:
                all_npmaudit = value

    elif query == 'low':
        all_npmaudit_low = npmaudit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_npmaudit_low.items():
            if value is None:
                all_npmaudit = '0'
            else:
                all_npmaudit = value

    return all_npmaudit


def all_nodejsscan(username, project_id, query):
    all_nodejsscan = None
    if query == 'total':
        all_nodejsscan_scan = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_nodejsscan_scan.items():
            if value is None:
                all_nodejsscan = '0'
            else:
                all_nodejsscan = value

    elif query == 'high':

        all_nodejsscan_high = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_nodejsscan_high.items():
            if value is None:
                all_nodejsscan = '0'
            else:
                all_nodejsscan = value

    elif query == 'medium':
        all_nodejsscan_medium = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_nodejsscan_medium.items():
            if value is None:
                all_nodejsscan = '0'
            else:
                all_nodejsscan = value

    elif query == 'low':
        all_nodejsscan_low = nodejsscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_nodejsscan_low.items():
            if value is None:
                all_nodejsscan = '0'
            else:
                all_nodejsscan = value

    return all_nodejsscan


def all_semgrepscan(username, project_id, query):
    all_semgrepscan = None
    if query == 'total':
        all_semgrepscan_scan = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_semgrepscan_scan.items():
            if value is None:
                all_semgrepscan = '0'
            else:
                all_semgrepscan = value

    elif query == 'high':

        all_semgrepscan_high = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_semgrepscan_high.items():
            if value is None:
                all_semgrepscan = '0'
            else:
                all_semgrepscan = value

    elif query == 'medium':
        all_semgrepscan_medium = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_semgrepscan_medium.items():
            if value is None:
                all_semgrepscan = '0'
            else:
                all_semgrepscan = value

    elif query == 'low':
        all_semgrepscan_low = semgrepscan_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_semgrepscan_low.items():
            if value is None:
                all_semgrepscan = '0'
            else:
                all_semgrepscan = value

    return all_semgrepscan


def all_tfsec(username, project_id, query):
    all_tfsec = None
    if query == 'total':
        all_tfsec_scan = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_tfsec_scan.items():
            if value is None:
                all_tfsec = '0'
            else:
                all_tfsec = value

    elif query == 'high':

        all_tfsec_high = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_tfsec_high.items():
            if value is None:
                all_tfsec = '0'
            else:
                all_tfsec = value

    elif query == 'medium':
        all_tfsec_medium = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_tfsec_medium.items():
            if value is None:
                all_tfsec = '0'
            else:
                all_tfsec = value

    elif query == 'low':
        all_tfsec_low = tfsec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_tfsec_low.items():
            if value is None:
                all_tfsec = '0'
            else:
                all_tfsec = value

    return all_tfsec


def all_whitesource(username, project_id, query):
    all_whitesource = None
    if query == 'total':
        all_whitesource_scan = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_whitesource_scan.items():
            if value is None:
                all_whitesource = '0'
            else:
                all_whitesource = value

    elif query == 'high':

        all_whitesource_high = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_whitesource_high.items():
            if value is None:
                all_whitesource = '0'
            else:
                all_whitesource = value

    elif query == 'medium':
        all_whitesource_medium = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_whitesource_medium.items():
            if value is None:
                all_whitesource = '0'
            else:
                all_whitesource = value

    elif query == 'low':
        all_whitesource_low = whitesource_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_whitesource_low.items():
            if value is None:
                all_whitesource = '0'
            else:
                all_whitesource = value

    return all_whitesource


def all_checkmarx(username, project_id, query):
    all_checkmarx = None
    if query == 'total':
        all_checkmarx_scan = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_checkmarx_scan.items():
            if value is None:
                all_checkmarx = '0'
            else:
                all_checkmarx = value

    elif query == 'high':

        all_checkmarx_high = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_checkmarx_high.items():
            if value is None:
                all_checkmarx = '0'
            else:
                all_checkmarx = value

    elif query == 'medium':
        all_checkmarx_medium = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_checkmarx_medium.items():
            if value is None:
                all_checkmarx = '0'
            else:
                all_checkmarx = value

    elif query == 'low':
        all_checkmarx_low = checkmarx_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_checkmarx_low.items():
            if value is None:
                all_checkmarx = '0'
            else:
                all_checkmarx = value

    return all_checkmarx


def all_inspec(username, project_id, query):
    all_inspec = None
    if query == 'total':
        all_inspec_scan = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vuln'))

        for key, value in all_inspec_scan.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'failed':

        all_inspec_high = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('inspec_failed'))

        for key, value in all_inspec_high.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'passed':
        all_inspec_medium = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('inspec_passed'))

        for key, value in all_inspec_medium.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'skipped':
        all_inspec_low = inspec_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('inspec_skipped'))

        for key, value in all_inspec_low.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    return all_inspec


def all_dockle(username, project_id, query):
    all_dockle = None
    if query == 'total':
        all_dockle_scan = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vuln'))

        for key, value in all_dockle_scan.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    elif query == 'fatal':

        all_dockle_high = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('dockle_fatal'))

        for key, value in all_dockle_high.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    elif query == 'info':
        all_dockle_medium = dockle_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('dockle_info'))

        for key, value in all_dockle_medium.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    return all_dockle


def all_bandit(username, project_id, query):
    all_bandit = None
    if query == 'total':
        all_bandit_scan = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_bandit_scan.items():
            if value is None:
                all_bandit = '0'
            else:
                all_bandit = value

    elif query == 'high':

        all_bandit_high = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_bandit_high.items():
            if value is None:
                all_bandit = '0'
            else:
                all_bandit = value

    elif query == 'medium':
        all_bandit_medium = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_bandit_medium.items():
            if value is None:
                all_bandit = '0'
            else:
                all_bandit = value

    elif query == 'low':
        all_bandit_low = bandit_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_bandit_low.items():
            if value is None:
                all_bandit = '0'
            else:
                all_bandit = value

    return all_bandit


def all_openvas(username, project_id, query):
    all_openvas = None
    if query == 'total':
        all_openvas_scan = openvas_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_openvas_scan.items():
            if value is None:
                all_openvas = '0'
            else:
                all_openvas = value

    elif query == 'high':

        all_openvas_high = openvas_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_openvas_high.items():
            if value is None:
                all_openvas = '0'
            else:
                all_openvas = value

    elif query == 'medium':
        all_openvas_medium = openvas_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_openvas_medium.items():
            if value is None:
                all_openvas = '0'
            else:
                all_openvas = value

    elif query == 'low':
        all_openvas_low = openvas_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_openvas_low.items():
            if value is None:
                all_openvas = '0'
            else:
                all_openvas = value

    return all_openvas


def all_nessus(username, project_id, query):
    all_nessus = None
    if query == 'total':
        all_nessus_scan = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vuln'))

        for key, value in all_nessus_scan.items():
            if value is None:
                all_nessus = '0'
            else:
                all_nessus = value

    elif query == 'high':

        all_nessus_high = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_high'))

        for key, value in all_nessus_high.items():
            if value is None:
                all_nessus = '0'
            else:
                all_nessus = value

    elif query == 'medium':
        all_nessus_medium = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_medium'))

        for key, value in all_nessus_medium.items():
            if value is None:
                all_nessus = '0'
            else:
                all_nessus = value

    elif query == 'low':
        all_nessus_low = nessus_scan_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_low'))

        for key, value in all_nessus_low.items():
            if value is None:
                all_nessus = '0'
            else:
                all_nessus = value

    return all_nessus


def all_manual_scan(username, project_id, query):
    all_manual_scan = None
    if query == 'total':
        all_manual_scan_scan = manual_scans_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_manual_scan_scan.items():
            if value is None:
                all_manual_scan = '0'
            else:
                all_manual_scan = value

    elif query == 'high':

        all_manual_scan_high = manual_scans_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_manual_scan_high.items():
            if value is None:
                all_manual_scan = '0'
            else:
                all_manual_scan = value

    elif query == 'medium':
        all_manual_scan_medium = manual_scans_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_manual_scan_medium.items():
            if value is None:
                all_manual_scan = '0'
            else:
                all_manual_scan = value

    elif query == 'low':
        all_manual_scan_low = manual_scans_db.objects.filter(username=username, project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_manual_scan_low.items():
            if value is None:
                all_manual_scan = '0'
            else:
                all_manual_scan = value

    return all_manual_scan


def all_pentest_web(username, project_id, query):
    all_pentest_web = None
    if query == 'total':
        all_pentest_web_scan = manual_scans_db.objects.filter(username=username, pentest_type='web',
                                                              project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_pentest_web_scan.items():
            if value is None:
                all_pentest_web = '0'
            else:
                all_pentest_web = value

    elif query == 'high':

        all_pentest_web_high = manual_scans_db.objects.filter(username=username, pentest_type='web',
                                                              project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_pentest_web_high.items():
            if value is None:
                all_pentest_web = '0'
            else:
                all_pentest_web = value

    elif query == 'medium':
        all_pentest_web_medium = manual_scans_db.objects.filter(username=username, pentest_type='web',
                                                                project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_pentest_web_medium.items():
            if value is None:
                all_pentest_web = '0'
            else:
                all_pentest_web = value

    elif query == 'low':
        all_pentest_web_low = manual_scans_db.objects.filter(username=username, pentest_type='web',
                                                             project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_pentest_web_low.items():
            if value is None:
                all_pentest_web = '0'
            else:
                all_pentest_web = value

    return all_pentest_web


def all_pentest_net(username, project_id, query):
    all_pentest_net = None
    if query == 'total':
        all_pentest_net_scan = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                              project_id=project_id). \
            aggregate(Sum('total_vul'))

        for key, value in all_pentest_net_scan.items():
            if value is None:
                all_pentest_net = '0'
            else:
                all_pentest_net = value

    elif query == 'high':

        all_pentest_net_high = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                              project_id=project_id). \
            aggregate(Sum('high_vul'))

        for key, value in all_pentest_net_high.items():
            if value is None:
                all_pentest_net = '0'
            else:
                all_pentest_net = value

    elif query == 'medium':
        all_pentest_net_medium = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                                project_id=project_id). \
            aggregate(Sum('medium_vul'))

        for key, value in all_pentest_net_medium.items():
            if value is None:
                all_pentest_net = '0'
            else:
                all_pentest_net = value

    elif query == 'low':
        all_pentest_net_low = manual_scans_db.objects.filter(username=username, pentest_type='network',
                                                             project_id=project_id). \
            aggregate(Sum('low_vul'))

        for key, value in all_pentest_net_low.items():
            if value is None:
                all_pentest_net = '0'
            else:
                all_pentest_net = value

    return all_pentest_net


def all_vuln(username, project_id, query):
    all_vuln = 0

    # add your scanner name here <scannername>

    if query == 'total':
        # int(all_<scannername>(username=username, project_id=project_id, query=query)) + \
        all_vuln = int(all_zap(username=username, project_id=project_id, query=query)) + \
                   int(all_burp(username=username, project_id=project_id, query=query)) + \
                   int(all_openvas(username=username, project_id=project_id, query=query)) + \
                   int(all_nessus(username=username, project_id=project_id, query=query)) + \
                   int(all_arachni(username=username, project_id=project_id, query=query)) + \
                   int(all_netsparker(username=username, project_id=project_id, query=query)) + \
                   int(all_acunetix(username=username, project_id=project_id, query=query)) + \
                   int(all_webinspect(username=username, project_id=project_id, query=query)) + \
                   int(all_dependency(username=username, project_id=project_id, query=query)) + \
                   int(all_findbugs(username=username, project_id=project_id, query=query)) + \
                   int(all_clair(username=username, project_id=project_id, query=query)) + \
                   int(all_trivy(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsast(username=username, project_id=project_id, query=query)) + \
                   int(all_twistlock(username=username, project_id=project_id, query=query)) + \
                   int(all_brakeman(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsca(username=username, project_id=project_id, query=query)) + \
                   int(all_npmaudit(username=username, project_id=project_id, query=query)) + \
                   int(all_nodejsscan(username=username, project_id=project_id, query=query)) + \
                   int(all_semgrepscan(username=username, project_id=project_id, query=query)) + \
                   int(all_tfsec(username=username, project_id=project_id, query=query)) + \
                   int(all_whitesource(username=username, project_id=project_id, query=query)) + \
                   int(all_checkmarx(username=username, project_id=project_id, query=query)) + \
                   int(all_bandit(username=username, project_id=project_id, query=query)) + \
                   int(all_manual_scan(username=username, project_id=project_id, query=query))
    elif query == 'high':
        # add your scanner name <scannername>
        # int(all_<scannername>(username=username, project_id=project_id, query=query)) + \
        all_vuln = int(all_zap(username=username, project_id=project_id, query=query)) + \
                   int(all_burp(username=username, project_id=project_id, query=query)) + \
                   int(all_openvas(username=username, project_id=project_id, query=query)) + \
                   int(all_nessus(username=username, project_id=project_id, query=query)) + \
                   int(all_arachni(username=username, project_id=project_id, query=query)) + \
                   int(all_netsparker(username=username, project_id=project_id, query=query)) + \
                   int(all_acunetix(username=username, project_id=project_id, query=query)) + \
                   int(all_webinspect(username=username, project_id=project_id, query=query)) + \
                   int(all_dependency(username=username, project_id=project_id, query=query)) + \
                   int(all_findbugs(username=username, project_id=project_id, query=query)) + \
                   int(all_clair(username=username, project_id=project_id, query=query)) + \
                   int(all_trivy(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsast(username=username, project_id=project_id, query=query)) + \
                   int(all_twistlock(username=username, project_id=project_id, query=query)) + \
                   int(all_brakeman(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsca(username=username, project_id=project_id, query=query)) + \
                   int(all_npmaudit(username=username, project_id=project_id, query=query)) + \
                   int(all_nodejsscan(username=username, project_id=project_id, query=query)) + \
                   int(all_semgrepscan(username=username, project_id=project_id, query=query)) + \
                   int(all_tfsec(username=username, project_id=project_id, query=query)) + \
                   int(all_whitesource(username=username, project_id=project_id, query=query)) + \
                   int(all_checkmarx(username=username, project_id=project_id, query=query)) + \
                   int(all_bandit(username=username, project_id=project_id, query=query)) + \
                   int(all_manual_scan(username=username, project_id=project_id, query=query))
    elif query == 'medium':
        # add your scanner name here <scannername>
        # int(all_<scannername>(username=username, project_id=project_id, query=query)) + \
        all_vuln = int(all_zap(username=username, project_id=project_id, query=query)) + \
                   int(all_burp(username=username, project_id=project_id, query=query)) + \
                   int(all_openvas(username=username, project_id=project_id, query=query)) + \
                   int(all_nessus(username=username, project_id=project_id, query=query)) + \
                   int(all_arachni(username=username, project_id=project_id, query=query)) + \
                   int(all_netsparker(username=username, project_id=project_id, query=query)) + \
                   int(all_acunetix(username=username, project_id=project_id, query=query)) + \
                   int(all_webinspect(username=username, project_id=project_id, query=query)) + \
                   int(all_dependency(username=username, project_id=project_id, query=query)) + \
                   int(all_findbugs(username=username, project_id=project_id, query=query)) + \
                   int(all_clair(username=username, project_id=project_id, query=query)) + \
                   int(all_trivy(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsast(username=username, project_id=project_id, query=query)) + \
                   int(all_twistlock(username=username, project_id=project_id, query=query)) + \
                   int(all_brakeman(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsca(username=username, project_id=project_id, query=query)) + \
                   int(all_npmaudit(username=username, project_id=project_id, query=query)) + \
                   int(all_nodejsscan(username=username, project_id=project_id, query=query)) + \
                   int(all_semgrepscan(username=username, project_id=project_id, query=query)) + \
                   int(all_tfsec(username=username, project_id=project_id, query=query)) + \
                   int(all_whitesource(username=username, project_id=project_id, query=query)) + \
                   int(all_checkmarx(username=username, project_id=project_id, query=query)) + \
                   int(all_bandit(username=username, project_id=project_id, query=query)) + \
                   int(all_manual_scan(username=username, project_id=project_id, query=query))
    elif query == 'low':
        # add your scannername here <scannername>
        # int(all_<scannername>(username=username, project_id=project_id, query=query)) + \
        all_vuln = int(all_zap(username=username, project_id=project_id, query=query)) + \
                   int(all_burp(username=username, project_id=project_id, query=query)) + \
                   int(all_openvas(username=username, project_id=project_id, query=query)) + \
                   int(all_nessus(username=username, project_id=project_id, query=query)) + \
                   int(all_arachni(username=username, project_id=project_id, query=query)) + \
                   int(all_netsparker(username=username, project_id=project_id, query=query)) + \
                   int(all_acunetix(username=username, project_id=project_id, query=query)) + \
                   int(all_webinspect(username=username, project_id=project_id, query=query)) + \
                   int(all_dependency(username=username, project_id=project_id, query=query)) + \
                   int(all_findbugs(username=username, project_id=project_id, query=query)) + \
                   int(all_clair(username=username, project_id=project_id, query=query)) + \
                   int(all_trivy(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsast(username=username, project_id=project_id, query=query)) + \
                   int(all_twistlock(username=username, project_id=project_id, query=query)) + \
                   int(all_brakeman(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + \
                   int(all_gitlabsca(username=username, project_id=project_id, query=query)) + \
                   int(all_npmaudit(username=username, project_id=project_id, query=query)) + \
                   int(all_nodejsscan(username=username, project_id=project_id, query=query)) + \
                   int(all_semgrepscan(username=username, project_id=project_id, query=query)) + \
                   int(all_tfsec(username=username, project_id=project_id, query=query)) + \
                   int(all_whitesource(username=username, project_id=project_id, query=query)) + \
                   int(all_checkmarx(username=username, project_id=project_id, query=query)) + \
                   int(all_bandit(username=username, project_id=project_id, query=query)) + \
                   int(all_manual_scan(username=username, project_id=project_id, query=query))

    return all_vuln


def all_web(username, project_id, query):
    all_web = 0

    if query == 'total':
        all_web = int(all_zap(username=username, project_id=project_id, query=query)) + int(
            all_burp(username=username, project_id=project_id, query=query)) + int(
            all_pentest_web(username=username, project_id=project_id, query=query)) + int(
            all_arachni(username=username, project_id=project_id, query=query)) + \
                  int(all_netsparker(username=username, project_id=project_id, query=query)) + int(
            all_webinspect(username=username, project_id=project_id, query=query)) + int(
            all_acunetix(username=username, project_id=project_id, query=query))
    elif query == 'high':
        all_web = int(all_zap(username=username, project_id=project_id, query=query)) + int(
            all_burp(username=username, project_id=project_id, query=query)) + int(
            all_pentest_web(username=username, project_id=project_id, query=query)) + int(
            all_arachni(username=username, project_id=project_id, query=query)) + \
                  int(all_netsparker(username=username, project_id=project_id, query=query)) + int(
            all_webinspect(username=username, project_id=project_id, query=query)) + int(
            all_acunetix(username=username, project_id=project_id, query=query))
    elif query == 'medium':
        all_web = int(all_zap(username=username, project_id=project_id, query=query)) + int(
            all_burp(username=username, project_id=project_id, query=query)) + int(
            all_pentest_web(username=username, project_id=project_id, query=query)) + int(
            all_arachni(username=username, project_id=project_id, query=query)) + \
                  int(all_netsparker(username=username, project_id=project_id, query=query)) + int(
            all_webinspect(username=username, project_id=project_id, query=query)) + int(
            all_acunetix(username=username, project_id=project_id, query=query))
    elif query == 'low':
        all_web = int(all_zap(username=username, project_id=project_id, query=query)) + int(
            all_burp(username=username, project_id=project_id, query=query)) + int(
            all_pentest_web(username=username, project_id=project_id, query=query)) + int(
            all_arachni(username=username, project_id=project_id, query=query)) + \
                  int(all_netsparker(username=username, project_id=project_id, query=query)) + int(
            all_webinspect(username=username, project_id=project_id, query=query)) + int(
            all_acunetix(username=username, project_id=project_id, query=query))

    return all_web


def all_net(username, project_id, query):
    all_net = 0

    if query == 'total':
        all_net = int(all_openvas(username=username, project_id=project_id, query=query)) + int(
            all_nessus(username=username, project_id=project_id, query=query)) + int(
            all_pentest_net(username=username, project_id=project_id, query=query))
    elif query == 'high':
        all_net = int(all_openvas(username=username, project_id=project_id, query=query)) + int(
            all_nessus(username=username, project_id=project_id, query=query)) + int(
            all_pentest_net(username=username, project_id=project_id, query=query))
    elif query == 'medium':
        all_net = int(all_openvas(username=username, project_id=project_id, query=query)) + int(
            all_nessus(username=username, project_id=project_id, query=query)) + int(
            all_pentest_net(username=username, project_id=project_id, query=query))
    elif query == 'low':
        all_net = int(all_openvas(username=username, project_id=project_id, query=query)) + int(
            all_nessus(username=username, project_id=project_id, query=query)) + int(
            all_pentest_net(username=username, project_id=project_id, query=query))

    return all_net


def all_compliance(username, project_id, query):
    all_compliance = 0

    if query == 'total':
        all_compliance = int(all_inspec(username=username, project_id=project_id, query=query)) + int(
            all_dockle(username=username, project_id=project_id, query=query))
    elif query == 'failed':
        all_compliance = int(all_inspec(username=username, project_id=project_id, query=query)) + int(
            all_dockle(username=username, project_id=project_id, query='fatal'))
    elif query == 'passed':
        all_compliance = int(all_inspec(username=username, project_id=project_id, query=query)) + int(
            all_dockle(username=username, project_id=project_id, query='info'))
    elif query == 'skipped':
        all_compliance = int(all_inspec(username=username, project_id=project_id, query=query))

    return all_compliance


def all_static(username, project_id, query):
    all_static = 0
    # add your scannername <scannername>
    # all_<scannername>(username=username, project_id=project_id, query=query)) + int(
    if query == 'total':
        all_static = int(all_dependency(username=username, project_id=project_id, query=query)) + int(
            all_findbugs(username=username, project_id=project_id, query=query)) + int(
            all_bandit(username=username, project_id=project_id, query=query)) + int(
            all_clair(username=username, project_id=project_id, query=query)) + int(
            all_trivy(username=username, project_id=project_id, query=query)) + int(
            all_npmaudit(username=username, project_id=project_id, query=query)) + int(
            all_nodejsscan(username=username, project_id=project_id, query=query)) + int(
            all_semgrepscan(username=username, project_id=project_id, query=query)) + int(
            all_tfsec(username=username, project_id=project_id, query=query)) + int(
            all_whitesource(username=username, project_id=project_id, query=query)) + int(
            all_checkmarx(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsast(username=username, project_id=project_id, query=query)) + int(
            all_twistlock(username=username, project_id=project_id, query=query)) + int(
            all_brakeman(username=username, project_id=project_id, query=query)) + int(
            all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsca(username=username, project_id=project_id, query=query))
    elif query == 'high':
        # add your scanner name here <scannername>
        all_static = int(all_dependency(username=username, project_id=project_id, query=query)) + int(
            all_findbugs(username=username, project_id=project_id, query=query)) + int(
            all_bandit(username=username, project_id=project_id, query=query)) + int(
            all_clair(username=username, project_id=project_id, query=query)) + int(
            all_trivy(username=username, project_id=project_id, query=query)) + int(
            all_npmaudit(username=username, project_id=project_id, query=query)) + int(
            all_nodejsscan(username=username, project_id=project_id, query=query)) + int(
            all_semgrepscan(username=username, project_id=project_id, query=query)) + int(
            all_tfsec(username=username, project_id=project_id, query=query)) + int(
            all_whitesource(username=username, project_id=project_id, query=query)) + int(
            all_checkmarx(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsast(username=username, project_id=project_id, query=query)) + int(
            all_twistlock(username=username, project_id=project_id, query=query)) + int(
            all_brakeman(username=username, project_id=project_id, query=query)) + int(
            all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsca(username=username, project_id=project_id, query=query))
    elif query == 'medium':
        # add your scanner name here <scannername>
        all_static = int(all_dependency(username=username, project_id=project_id, query=query)) + int(
            all_findbugs(username=username, project_id=project_id, query=query)) + int(
            all_bandit(username=username, project_id=project_id, query=query)) + int(
            all_clair(username=username, project_id=project_id, query=query)) + int(
            all_trivy(username=username, project_id=project_id, query=query)) + int(
            all_npmaudit(username=username, project_id=project_id, query=query)) + int(
            all_nodejsscan(username=username, project_id=project_id, query=query)) + int(
            all_semgrepscan(username=username, project_id=project_id, query=query)) + int(
            all_tfsec(username=username, project_id=project_id, query=query)) + int(
            all_whitesource(username=username, project_id=project_id, query=query)) + int(
            all_checkmarx(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsast(username=username, project_id=project_id, query=query)) + int(
            all_twistlock(username=username, project_id=project_id, query=query)) + int(
            all_brakeman(username=username, project_id=project_id, query=query)) + int(
            all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsca(username=username, project_id=project_id, query=query))
    elif query == 'low':
        # add your scanner name here <scannername>
        all_static = int(all_dependency(username=username, project_id=project_id, query=query)) + int(
            all_findbugs(username=username, project_id=project_id, query=query)) + int(
            all_bandit(username=username, project_id=project_id, query=query)) + int(
            all_clair(username=username, project_id=project_id, query=query)) + int(
            all_trivy(username=username, project_id=project_id, query=query)) + int(
            all_npmaudit(username=username, project_id=project_id, query=query)) + int(
            all_nodejsscan(username=username, project_id=project_id, query=query)) + int(
            all_semgrepscan(username=username, project_id=project_id, query=query)) + int(
            all_tfsec(username=username, project_id=project_id, query=query)) + int(
            all_whitesource(username=username, project_id=project_id, query=query)) + int(
            all_checkmarx(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsast(username=username, project_id=project_id, query=query)) + int(
            all_twistlock(username=username, project_id=project_id, query=query)) + int(
            all_brakeman(username=username, project_id=project_id, query=query)) + int(
            all_gitlabcontainerscan(username=username, project_id=project_id, query=query)) + int(
            all_gitlabsca(username=username, project_id=project_id, query=query))

    return all_static


def all_vuln_count(username, project_id, query):
    all_data = 0
    # <scannername>_all_high = <scannername>_scan_results_db.objects.filter(username=username, Severity='HIGH',
    #                                                                     project_id=project_id)
    if query == 'High':
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id, severity='High', scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, Severity='HIGH',
                                                                        project_id=project_id)
        
        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, severity='High',
                                                                        project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='HIGH',
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
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='High',
                                                                project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='High',
                                                                 project_id=project_id)
        # add your scanner name here <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'Medium':
        # All Medium
        # add your scanner name <scannername>
        # <scannername>_all_high = <scannername>_scan_results_db.objects.filter(username=username, Severity='Medium',
        #                                                                 project_id=project_id)
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          severity='Medium', scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, Severity='Medium',
                                                                        project_id=project_id)
        
        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                        project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='Medium',
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
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='Medium',
                                                                project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Medium',
                                                                 project_id=project_id)
        # add your scannername here <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'Low':
        # add your scannername here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          severity='Low', scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, Severity='Low',
                                                                        project_id=project_id)

        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, severity='Low',
                                                                        project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          Severity='Low',
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
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, risk_factor='Low',
                                                                project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, severity='Low',
                                                                 project_id=project_id)
        # add your scanner name <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'Total':
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, project_id=project_id)

        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, project_id=project_id)

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id)

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id)

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id)

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id)

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id)
        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id)

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id)
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id)

        pentest_all_high = manual_scan_results_db.objects.filter(username=username, project_id=project_id)

        # add your scanner name <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'False':
        # add your scanner name <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          false_positive='Yes', scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')
        
        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        false_positive='Yes')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id,
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
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                false_positive='Yes')
        # add your scanner name <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'Close':
        # add your scanner name <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          vuln_status='Closed', scanner='zap')
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

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')
        
        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Closed')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id,
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
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                vuln_status='Closed')
        # add your scanner name here <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    elif query == 'Open':
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                          vuln_status='Open', scanner='zap')
        arachni_all_high = arachni_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                 vuln_status='Open')
        webinspect_all_high = webinspect_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Open')

        netsparker_all_high = netsparker_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                       vuln_status='Open')
        acunetix_all_high = acunetix_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                                   vuln_status='Open')
        burp_all_high = burp_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                           vuln_status='Open')

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                  project_id=project_id,
                                                                                  vuln_status='Open')
        findbugs_all_high = findbugs_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Open')
        clair_all_high = clair_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Open')

        trivy_all_high = trivy_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Open')

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      vuln_status='Open')

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Open')

        twistlock_all_high = twistlock_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Open')

        brakeman_all_high = brakeman_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Open')

        gitlabcontainerscan_all_high = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                          project_id=project_id,
                                                                                          vuln_status='Open')

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                    vuln_status='Open')

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                        vuln_status='Open')

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Open')

        tfsec_all_high = tfsec_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                              vuln_status='Open')

        whitesource_all_high = whitesource_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                          vuln_status='Open')

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                      vuln_status='Open')

        openvas_all_high = ov_scan_result_db.objects.filter(username=username, project_id=project_id,
                                                            vuln_status='Open')
        nessus_all_high = nessus_scan_results_db.objects.filter(username=username, project_id=project_id,
                                                                vuln_status='Open')
        # add your scanner name here <scannername>
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
                         twistlock_all_high,
                         brakeman_all_high,
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

    return all_data


def all_vuln_count_data(username, project_id, query):
    all_data = 0

    if query == 'false':
        # add your scanner name here <scannername>
        zap_false_positive = WebScanResultsDb.objects.filter(username=username, false_positive='Yes',
                                                                project_id=project_id, scanner='zap')
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

        twistlock_false_positive = twistlock_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                              project_id=project_id)

        brakeman_false_positive = brakeman_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                              project_id=project_id)
        gitlabcontainerscan_false_positive = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                                false_positive='Yes',
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
        nessus_false_positive = nessus_scan_results_db.objects.filter(username=username, false_positive='Yes',
                                                                      project_id=project_id)
        # add your scanner name <scannername>
        all_data = int(len(zap_false_positive)) + \
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
                   int(len(twistlock_false_positive)) + \
                   int(len(brakeman_false_positive)) + \
                   int(len(gitlabcontainerscan_false_positive)) + \
                   int(len(gitlabsca_false_positive)) + \
                   int(len(npmaudit_false_positive)) + \
                   int(len(nodejsscan_false_positive)) + \
                   int(len(semgrepscan_false_positive)) + \
                   int(len(tfsec_false_positive)) + \
                   int(len(whitesource_false_positive)) + \
                   int(len(checkmarx_false_positive)) + \
                   int(len(bandit_false_positive))
    elif query == 'Closed':
        # add your scanner name here <scannername>
        zap_closed_vuln = WebScanResultsDb.objects.filter(username=username, vuln_status='Closed',
                                                             project_id=project_id, scanner='zap')
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
        nessus_closed_vuln = nessus_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                   project_id=project_id)

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

        twistlock_closed_vuln = twistlock_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                           project_id=project_id)

        brakeman_closed_vuln = brakeman_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                           project_id=project_id)

        gitlabcontainerscan_closed_vuln = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                             vuln_status='Closed',
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
        pentest_closed_vuln = manual_scan_results_db.objects.filter(username=username, vuln_status='Closed',
                                                                    project_id=project_id)
        # add your scanner name here <scannername>
        all_data = int(len(zap_closed_vuln)) + \
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
                   int(len(twistlock_closed_vuln)) + \
                   int(len(brakeman_closed_vuln)) + \
                   int(len(gitlabcontainerscan_closed_vuln)) + \
                   int(len(gitlabsca_closed_vuln)) + \
                   int(len(npmaudit_closed_vuln)) + \
                   int(len(nodejsscan_closed_vuln)) + \
                   int(len(semgrepscan_closed_vuln)) + \
                   int(len(tfsec_closed_vuln)) + \
                   int(len(whitesource_closed_vuln)) + \
                   int(len(checkmarx_closed_vuln)) + \
                   int(len(pentest_closed_vuln)) + \
                   int(len(bandit_closed_vuln))

    elif query == 'Open':
        # add your scanner name here <scannername>
        zap_open_vuln = WebScanResultsDb.objects.filter(username=username, vuln_status='Open',
                                                             project_id=project_id, scanner='zap')
        burp_open_vuln = burp_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                              project_id=project_id)
        arachni_open_vuln = arachni_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                                    project_id=project_id)
        netsparker_open_vuln = netsparker_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                                          project_id=project_id)
        webinspect_open_vuln = webinspect_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                                          project_id=project_id)
        acunetix_open_vuln = acunetix_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                                      project_id=project_id)
        openvas_open_vuln = ov_scan_result_db.objects.filter(username=username, vuln_status='Open',
                                                               project_id=project_id)
        nessus_open_vuln = nessus_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                   project_id=project_id)

        dependencycheck_open_vuln = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                     vuln_status='Open',
                                                                                     project_id=project_id)
        findbugs_open_vuln = findbugs_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                       project_id=project_id)
        clair_open_vuln = clair_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                 project_id=project_id)
        trivy_open_vuln = trivy_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                 project_id=project_id)
        gitlabsast_open_vuln = gitlabsast_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                           project_id=project_id)
        twistlock_open_vuln = twistlock_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                           project_id=project_id)
        brakeman_open_vuln = brakeman_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                           project_id=project_id)
        gitlabcontainerscan_open_vuln = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                                             vuln_status='Open',
                                                                                             project_id=project_id)
        gitlabsca_open_vuln = gitlabsca_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                         project_id=project_id)
        npmaudit_open_vuln = npmaudit_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                       project_id=project_id)
        nodejsscan_open_vuln = nodejsscan_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                           project_id=project_id)
        semgrepscan_open_vuln = semgrepscan_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                             project_id=project_id)
        tfsec_open_vuln = tfsec_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                 project_id=project_id)
        whitesource_open_vuln = whitesource_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                             project_id=project_id)

        checkmarx_open_vuln = checkmarx_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                         project_id=project_id)

        bandit_open_vuln = bandit_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                   project_id=project_id)
        pentest_open_vuln = manual_scan_results_db.objects.filter(username=username, vuln_status='Open',
                                                                    project_id=project_id)
        # add your scanner name here <scannername>
        all_data = int(len(zap_open_vuln)) + \
                   int(len(burp_open_vuln)) + \
                   int(len(arachni_open_vuln)) + \
                   int(len(acunetix_open_vuln)) + \
                   int(len(netsparker_open_vuln)) + \
                   int(len(webinspect_open_vuln)) + \
                   int(len(openvas_open_vuln)) + \
                   int(len(nessus_open_vuln)) + \
                   int(len(dependencycheck_open_vuln)) + \
                   int(len(findbugs_open_vuln)) + \
                   int(len(clair_open_vuln)) + \
                   int(len(trivy_open_vuln)) + \
                   int(len(gitlabsast_open_vuln)) + \
                   int(len(twistlock_open_vuln)) + \
                   int(len(brakeman_open_vuln)) + \
                   int(len(gitlabcontainerscan_open_vuln)) + \
                   int(len(gitlabsca_open_vuln)) + \
                   int(len(npmaudit_open_vuln)) + \
                   int(len(nodejsscan_open_vuln)) + \
                   int(len(semgrepscan_open_vuln)) + \
                   int(len(tfsec_open_vuln)) + \
                   int(len(whitesource_open_vuln)) + \
                   int(len(checkmarx_open_vuln)) + \
                   int(len(pentest_open_vuln)) + \
                   int(len(bandit_open_vuln))

    return all_data
