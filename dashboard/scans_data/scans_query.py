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

from itertools import chain

from django.db.models import Sum

from compliance.models import dockle_scan_db, inspec_scan_db
# import pentest database db <scannername>
from manual_scan.models import manual_scan_results_db, manual_scans_db
# import static scanners database model db <scannername>
from staticscanners.models import (StaticScansDb, StaticScanResultsDb)
# import your web scanners db <scannername>
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from compliance.models import dockle_scan_results_db, dockle_scan_db, inspec_scan_results_db, inspec_scan_db

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


def all_sast(scanner, username, project_id, query):
    all_sast = None
    if query == "total":
        all_sast_scan = StaticScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("total_vul"))

        for key, value in all_sast_scan.items():
            if value is None:
                all_sast = "0"
            else:
                all_sast = value

    elif query == "high":

        all_sast_high = StaticScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("high_vul"))

        for key, value in all_sast_high.items():
            if value is None:
                all_sast = "0"
            else:
                all_sast = value

    elif query == "medium":
        all_sast_medium = StaticScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("medium_vul"))

        for key, value in all_sast_medium.items():
            if value is None:
                all_sast = "0"
            else:
                all_sast = value

    elif query == "low":
        all_sast_low = StaticScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("low_vul"))

        for key, value in all_sast_low.items():
            if value is None:
                all_sast = "0"
            else:
                all_sast = value

    return all_sast


def all_web(scanner, username, project_id, query):
    all_web = None

    if query == "total":
        all_web_scan = WebScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("total_vul"))

        for key, value in all_web_scan.items():
            if value is None:
                all_web = "0"
            else:
                all_web = value

    elif query == "high":
        all_web_high = WebScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("high_vul"))

        for key, value in all_web_high.items():
            if value is None:
                all_web = "0"
            else:
                all_web = value

        def all_web_scan():
            WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner=scanner
            ).aggregate(Sum("high_vul"))
            return all_web_scan

    elif query == "medium":
        all_web_medium = WebScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("medium_vul"))

        for key, value in all_web_medium.items():
            if value is None:
                all_web = "0"
            else:
                all_web = value

    elif query == "low":
        all_web_low = WebScansDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("low_vul"))

        for key, value in all_web_low.items():
            if value is None:
                all_web = "0"
            else:
                all_web = value

    return all_web


def all_net(scanner, username, project_id, query):
    all_net = None
    if query == "total":
        all_net_scan = NetworkScanDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("total_vul"))

        for key, value in all_net_scan.items():
            if value is None:
                all_net = "0"
            else:
                all_net = value

    elif query == "high":

        all_net_high = NetworkScanDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("high_vul"))

        for key, value in all_net_high.items():
            if value is None:
                all_net = "0"
            else:
                all_net = value

    elif query == "medium":
        all_net_medium = NetworkScanDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("medium_vul"))

        for key, value in all_net_medium.items():
            if value is None:
                all_net = "0"
            else:
                all_net = value

    elif query == "low":
        all_net_low = NetworkScanDb.objects.filter(
            username=username, project_id=project_id, scanner=scanner
        ).aggregate(Sum("low_vul"))

        for key, value in all_net_low.items():
            if value is None:
                all_net = "0"
            else:
                all_net = value

    return all_net


def all_manual_scan(username, project_id, query):
    all_manual_scan = None
    if query == "total":
        all_manual_scan_scan = manual_scans_db.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_manual_scan_scan.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "high":

        all_manual_scan_high = manual_scans_db.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_manual_scan_high.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "medium":
        all_manual_scan_medium = manual_scans_db.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_manual_scan_medium.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "low":
        all_manual_scan_low = manual_scans_db.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_manual_scan_low.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    return all_manual_scan


def all_pentest_web(username, project_id, query):
    all_pentest_web = None
    if query == "total":
        all_pentest_web_scan = manual_scans_db.objects.filter(
            username=username, pentest_type="web", project_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_pentest_web_scan.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "high":

        all_pentest_web_high = manual_scans_db.objects.filter(
            username=username, pentest_type="web", project_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_pentest_web_high.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "medium":
        all_pentest_web_medium = manual_scans_db.objects.filter(
            username=username, pentest_type="web", project_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_pentest_web_medium.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "low":
        all_pentest_web_low = manual_scans_db.objects.filter(
            username=username, pentest_type="web", project_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_pentest_web_low.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    return all_pentest_web


def all_pentest_net(username, project_id, query):
    all_pentest_net = None
    if query == "total":
        all_pentest_net_scan = manual_scans_db.objects.filter(
            username=username, pentest_type="network", project_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_pentest_net_scan.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "high":

        all_pentest_net_high = manual_scans_db.objects.filter(
            username=username, pentest_type="network", project_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_pentest_net_high.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "medium":
        all_pentest_net_medium = manual_scans_db.objects.filter(
            username=username, pentest_type="network", project_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_pentest_net_medium.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "low":
        all_pentest_net_low = manual_scans_db.objects.filter(
            username=username, pentest_type="network", project_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_pentest_net_low.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    return all_pentest_net


def all_vuln(username, project_id, query, scanner):
    all_vuln = 0

    # add your scanner name here <scannername>

    if query == "total":
        all_vuln = (
                int(all_sast(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_web(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_net(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "high":
        all_vuln = (
                int(all_sast(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_web(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_net(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "medium":
        all_vuln = (
                int(all_sast(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_web(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_net(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "low":
        all_vuln = (
                int(all_sast(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_web(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_net(scanner=scanner, username=username, project_id=project_id, query=query))
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    return all_vuln



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


def all_compliance(username, project_id, query):
    all_compliance = 0

    if query == "total":
        all_compliance = int(
            all_inspec(username=username, project_id=project_id, query=query)
        ) + int(all_dockle(username=username, project_id=project_id, query=query))
    elif query == "failed":
        all_compliance = int(
            all_inspec(username=username, project_id=project_id, query=query)
        ) + int(all_dockle(username=username, project_id=project_id, query="fatal"))
    elif query == "passed":
        all_compliance = int(
            all_inspec(username=username, project_id=project_id, query=query)
        ) + int(all_dockle(username=username, project_id=project_id, query="info"))
    elif query == "skipped":
        all_compliance = int(
            all_inspec(username=username, project_id=project_id, query=query)
        )

    return all_compliance


def all_vuln_count(scanner, username, project_id, severity):

    all_web_high = WebScanResultsDb.objects.filter(
        username=username, project_id=project_id, severity=severity, scanner=scanner
    )
    all_sast_high = StaticScanResultsDb.objects.filter(
        username=username, project_id=project_id, severity=severity, scanner=scanner
    )

    all_net_high = NetworkScanResultsDb.objects.filter(
        username=username, threat=severity, project_id=project_id, scanner=scanner
    )

    pentest_all_high = manual_scan_results_db.objects.filter(
        username=username, severity=severity, project_id=project_id
    )
    # add your scanner name here <scannername>
    all_data = chain(
        all_web_high,
        all_sast_high,
        all_net_high,
        pentest_all_high
    )