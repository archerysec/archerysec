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
from manual_scan.models import manual_scan_results_db, manual_scans_db
from staticscanners.models import (StaticScansDb, StaticScanResultsDb)
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from compliance.models import dockle_scan_results_db, dockle_scan_db, inspec_scan_results_db, inspec_scan_db

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def all_sast_dat(scanner, username, project_id, query):
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


def all_web_dat(scanner, username, project_id, query):
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


def all_net_dat(scanner, username, project_id, query):
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


def all_vuln(username, project_id, query):
    all_vuln = 0

    if query == "total":

        all_sast_scan = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])

        all_dast_scan = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])

        all_net_scan = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "high":

        all_sast_scan = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])

        all_dast_scan = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])

        all_net_scan = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "medium":

        all_sast_scan = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

        all_dast_scan = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

        all_net_scan = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    elif query == "low":
        all_sast_scan = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

        all_dast_scan = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

        all_net_scan = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(username=username, project_id=project_id, query=query))
        )
    return all_vuln


def all_web(username, project_id, query):
    all_web = 0

    if query == 'total':
        all_web = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])

    elif query == 'high':
        all_web = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])

    elif query == 'medium':
        all_web = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

    elif query == 'low':
        all_web = int(WebScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

    return all_web


def all_net(username, project_id, query):
    all_net = 0

    if query == 'total':
        all_net = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])
    elif query == 'high':
        all_net = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])
    elif query == 'medium':
        all_net = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

    elif query == 'low':
        all_net = int(NetworkScanDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

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
        all_static = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("total_vul"))['total_vul__sum'])
    elif query == 'high':
        all_static = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("high_vul"))['high_vul__sum'])
    elif query == 'medium':
        all_static = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

    elif query == 'low':
        all_static = int(StaticScansDb.objects.filter(
            username=username, project_id=project_id
        ).aggregate(Sum("low_vul"))['low_vul__sum'])

    return all_static


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


def all_vuln_count(username, project_id, query):
    all_data = 0
    if query == 'High':
        web_all_high = WebScanResultsDb.objects.filter(username=username,
                                                       project_id=project_id,
                                                       severity='High',
                                                       )

        sast_all_high = StaticScanResultsDb.objects.filter(username=username,
                                                           project_id=project_id,
                                                           severity='High'
                                                           )

        net_all_high = NetworkScanResultsDb.objects.filter(username=username,
                                                           severity='High',
                                                           project_id=project_id
                                                           )

        pentest_all_high = manual_scan_results_db.objects.filter(username=username,
                                                                 severity='High',
                                                                 project_id=project_id
                                                                 )
        all_data = chain(web_all_high,
                         sast_all_high,
                         net_all_high,
                         pentest_all_high,
                         )

    elif query == 'Medium':
        web_all_medium = WebScanResultsDb.objects.filter(username=username,
                                                         project_id=project_id,
                                                         severity='Medium',
                                                         )

        sast_all_medium = StaticScanResultsDb.objects.filter(username=username,
                                                             project_id=project_id,
                                                             severity='Medium'
                                                             )

        net_all_medium = NetworkScanResultsDb.objects.filter(username=username,
                                                             severity='Medium',
                                                             project_id=project_id
                                                             )

        pentest_all_medium = manual_scan_results_db.objects.filter(username=username,
                                                                   severity='Medium',
                                                                   project_id=project_id
                                                                   )

        all_data = chain(web_all_medium,
                         sast_all_medium,
                         net_all_medium,
                         pentest_all_medium,
                         )

    elif query == 'Low':

        web_all_low = WebScanResultsDb.objects.filter(username=username,
                                                      project_id=project_id,
                                                      severity='Low',
                                                      )

        sast_all_low = StaticScanResultsDb.objects.filter(username=username,
                                                          project_id=project_id,
                                                          severity='Low'
                                                          )

        net_all_low = NetworkScanResultsDb.objects.filter(username=username,
                                                          severity='Low',
                                                          project_id=project_id
                                                          )

        pentest_all_low = manual_scan_results_db.objects.filter(username=username,
                                                                severity='Low',
                                                                project_id=project_id
                                                                )

        all_data = chain(web_all_low,
                         sast_all_low,
                         net_all_low,
                         pentest_all_low,
                         )

    elif query == 'Total':
        web_all = WebScanResultsDb.objects.filter(username=username,
                                                  project_id=project_id,
                                                  )

        sast_all = StaticScanResultsDb.objects.filter(username=username,
                                                      project_id=project_id,
                                                      )

        net_all = NetworkScanResultsDb.objects.filter(username=username,
                                                      project_id=project_id
                                                      )

        pentest_all = manual_scan_results_db.objects.filter(username=username,
                                                            project_id=project_id
                                                            )

        all_data = chain(web_all,
                         sast_all,
                         net_all,
                         pentest_all,
                         )

    elif query == 'False':
        web_all_false = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                        false_positive='Yes')

        sast_all_false = StaticScanResultsDb.objects.filter(username=username,
                                                            project_id=project_id,
                                                            false_positive='Yes')

        net_all_false = NetworkScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                            false_positive='Yes')
        all_data = chain(web_all_false,
                         sast_all_false,
                         net_all_false,
                         )

    elif query == 'Close':
        web_all_close = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                        vuln_status='Closed')

        sast_all_close = StaticScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                            vuln_status='Closed')

        net_all_close = NetworkScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                            vuln_status='Closed')
        all_data = chain(web_all_close,
                         sast_all_close,
                         net_all_close,
                         )

    elif query == 'Open':

        web_all_open = WebScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                       vuln_status='Open')

        sast_all_open = StaticScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                           vuln_status='Open')

        net_all_open = NetworkScanResultsDb.objects.filter(username=username, project_id=project_id,
                                                           vuln_status='Open')
        all_data = chain(web_all_open,
                         sast_all_open,
                         net_all_open,
                         )

    return all_data


def all_vuln_count_data(username, project_id, query):
    all_data = 0

    if query == 'false':
        web_false_positive = WebScanResultsDb.objects.filter(username=username, false_positive='Yes',
                                                             project_id=project_id)

        sast_false_positive = StaticScanResultsDb.objects.filter(username=username,
                                                                 false_positive='Yes',
                                                                 project_id=project_id)

        net_false_positive = NetworkScanResultsDb.objects.filter(username=username, false_positive='Yes',
                                                                 project_id=project_id)

        all_data = int(len(web_false_positive)) + \
                   int(len(sast_false_positive)) + \
                   int(len(net_false_positive))

    elif query == 'Closed':
        web_closed_vuln = WebScanResultsDb.objects.filter(username=username,
                                                          vuln_status='Closed',
                                                          project_id=project_id)

        net_closed_vuln = NetworkScanResultsDb.objects.filter(username=username,
                                                              vuln_status='Closed',
                                                              project_id=project_id)

        sast_closed_vuln = StaticScanResultsDb.objects.filter(username=username,
                                                              vuln_status='Closed',
                                                              project_id=project_id)

        pentest_closed_vuln = manual_scan_results_db.objects.filter(username=username,
                                                                    vuln_status='Closed',
                                                                    project_id=project_id)
        all_data = int(len(web_closed_vuln)) + \
                   int(len(net_closed_vuln)) + \
                   int(len(sast_closed_vuln)) + \
                   int(len(pentest_closed_vuln))


    elif query == 'Open':
        web_open_vuln = WebScanResultsDb.objects.filter(username=username,
                                                        vuln_status='Open',
                                                        project_id=project_id)
        net_open_vuln = NetworkScanResultsDb.objects.filter(username=username,
                                                            vuln_status='Open',
                                                            project_id=project_id)
        sast_open_vuln = StaticScanResultsDb.objects.filter(username=username,
                                                            vuln_status='Open',
                                                            project_id=project_id)

        pentest_open_vuln = manual_scan_results_db.objects.filter(username=username,
                                                                  vuln_status='Open',
                                                                  project_id=project_id)
        # add your scanner name here <scannername>
        all_data = int(len(web_open_vuln)) + \
                   int(len(net_open_vuln)) + \
                   int(len(sast_open_vuln)) + \
                   int(len(pentest_open_vuln))

    return all_data
