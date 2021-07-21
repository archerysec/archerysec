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
from compliance.models import DockleScanDb, InspecScanDb
from pentest.models import PentestScanDb, PentestScanResultsDb
from staticscanners.models import (StaticScansDb, StaticScanResultsDb)
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from compliance.models import DockleScanDb, DockleScanResultsDb, InspecScanDb, InspecScanResultsDb

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def all_manual_scan(project_id, query):
    all_manual_scan = None
    if query == "total":
        all_manual_scan_scan = PentestScanDb.objects.filter(
            project__uu_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_manual_scan_scan.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "high":

        all_manual_scan_high = PentestScanDb.objects.filter(
            project__uu_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_manual_scan_high.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "medium":
        all_manual_scan_medium = PentestScanDb.objects.filter(
            project__uu_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_manual_scan_medium.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    elif query == "low":
        all_manual_scan_low = PentestScanDb.objects.filter(
            project__uu_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_manual_scan_low.items():
            if value is None:
                all_manual_scan = "0"
            else:
                all_manual_scan = value

    return all_manual_scan


def all_pentest_web(project_id, query):
    all_pentest_web = None
    if query == "total":
        all_pentest_web_scan = PentestScanDb.objects.filter(
            pentest_type="web", project__uu_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_pentest_web_scan.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "high":

        all_pentest_web_high = PentestScanDb.objects.filter(
            pentest_type="web", project__uu_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_pentest_web_high.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "medium":
        all_pentest_web_medium = PentestScanDb.objects.filter(
            pentest_type="web", project__uu_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_pentest_web_medium.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    elif query == "low":
        all_pentest_web_low = PentestScanDb.objects.filter(
            pentest_type="web", project__uu_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_pentest_web_low.items():
            if value is None:
                all_pentest_web = "0"
            else:
                all_pentest_web = value

    return all_pentest_web


def all_pentest_net(project_id, query):
    all_pentest_net = None
    if query == "total":
        all_pentest_net_scan = PentestScanDb.objects.filter(
            pentest_type="network", project__uu_id=project_id
        ).aggregate(Sum("total_vul"))

        for key, value in all_pentest_net_scan.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "high":

        all_pentest_net_high = PentestScanDb.objects.filter(
            pentest_type="network", project__uu_id=project_id
        ).aggregate(Sum("high_vul"))

        for key, value in all_pentest_net_high.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "medium":
        all_pentest_net_medium = PentestScanDb.objects.filter(
            pentest_type="network", project__uu_id=project_id
        ).aggregate(Sum("medium_vul"))

        for key, value in all_pentest_net_medium.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    elif query == "low":
        all_pentest_net_low = PentestScanDb.objects.filter(
            pentest_type="network", project__uu_id=project_id
        ).aggregate(Sum("low_vul"))

        for key, value in all_pentest_net_low.items():
            if value is None:
                all_pentest_net = "0"
            else:
                all_pentest_net = value

    return all_pentest_net


def all_vuln(project_id, query):
    all_vuln = 0

    if query == "total":
        try:
            all_sast_scan = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])
        except Exception as e:
            print(e)
            all_sast_scan = 0

        try:
            all_dast_scan = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])
        except Exception as e:
            print(e)
            all_dast_scan = 0

        try:

            all_net_scan = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])
        except Exception as e:
            print(e)
            all_net_scan = 0

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(project_id=project_id, query=query))
        )
    elif query == "high":
        try:
            all_sast_scan = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            print(e)
            all_sast_scan = 0

        try:
            all_dast_scan = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            all_dast_scan = 0

        try:
            all_net_scan = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            all_net_scan = 0

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(project_id=project_id, query=query))
        )
    elif query == "medium":

        try:
            all_sast_scan = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])
        except Exception as e:
            print(e)
            all_sast_scan = 0

        try:
            all_dast_scan = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])
        except Exception as e:
            print(e)
            all_dast_scan = 0

        try:
            all_net_scan = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])

        except Exception as e:
            print(e)
            all_net_scan = 0

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(project_id=project_id, query=query))
        )
    elif query == "low":
        try:
            all_sast_scan = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_sast_scan = 0

        try:
            all_dast_scan = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_dast_scan = 0

        try:
            all_net_scan = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_net_scan = 0

        all_vuln = (
                int(all_sast_scan)
                + int(all_dast_scan)
                + int(all_net_scan)
                + int(all_manual_scan(project_id=project_id, query=query))
        )
    return all_vuln


def all_web(project_id, query):
    all_web = 0

    if query == 'total':

        try:
            all_web = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])

        except Exception as e:
            print(e)
            all_web = 0

    elif query == 'high':
        try:
            all_web = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            print(e)
            all_web = 0

    elif query == 'medium':
        try:
            all_web = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])
        except Exception as e:
            print(e)
            all_web = 0

    elif query == 'low':
        try:
            all_web = int(WebScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_web = 0

    return all_web


def all_net(project_id, query):
    all_net = 0

    if query == 'total':
        try:
            all_net = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])
        except Exception as e:
            print(e)
            all_net = 0

    elif query == 'high':
        try:
            all_net = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            print(e)
            all_net = 0
    elif query == 'medium':
        try:
            all_net = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])
        except Exception as e:
            print(e)
            all_net = 0

    elif query == 'low':
        try:
            all_net = int(NetworkScanDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_net = 0

    return all_net


def all_compliance(project_id, query):
    all_compliance = 0

    if query == 'total':
        all_compliance = int(all_inspec(project_id=project_id, query=query)) + int(
            all_dockle(project_id=project_id, query=query))
    elif query == 'failed':
        all_compliance = int(all_inspec(project_id=project_id, query=query)) + int(
            all_dockle(project_id=project_id, query='fatal'))
    elif query == 'passed':
        all_compliance = int(all_inspec(project_id=project_id, query=query)) + int(
            all_dockle(project_id=project_id, query='info'))
    elif query == 'skipped':
        all_compliance = int(all_inspec(project_id=project_id, query=query))

    return all_compliance


def all_static(project_id, query):
    all_static = 0

    if query == 'total':
        try:
            all_static = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("total_vul"))['total_vul__sum'])
        except Exception as e:
            print(e)
            all_static = 0
    elif query == 'high':
        try:
            all_static = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("high_vul"))['high_vul__sum'])
        except Exception as e:
            print(e)
            all_static = 0
    elif query == 'medium':
        try:
            all_static = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("medium_vul"))['medium_vul__sum'])
        except Exception as e:
            print(e)
            all_static = 0

    elif query == 'low':
        try:
            all_static = int(StaticScansDb.objects.filter(
                project__uu_id=project_id
            ).aggregate(Sum("low_vul"))['low_vul__sum'])
        except Exception as e:
            print(e)
            all_static = 0

    return all_static


def all_inspec(project_id, query):
    all_inspec = None
    if query == 'total':
        all_inspec_scan = InspecScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('total_vuln'))

        for key, value in all_inspec_scan.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'failed':

        all_inspec_high = InspecScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('inspec_failed'))

        for key, value in all_inspec_high.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'passed':
        all_inspec_medium = InspecScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('inspec_passed'))

        for key, value in all_inspec_medium.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    elif query == 'skipped':
        all_inspec_low = InspecScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('inspec_skipped'))

        for key, value in all_inspec_low.items():
            if value is None:
                all_inspec = '0'
            else:
                all_inspec = value

    return all_inspec


def all_dockle(project_id, query):
    all_dockle = None
    if query == 'total':
        all_dockle_scan = DockleScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('total_vuln'))

        for key, value in all_dockle_scan.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    elif query == 'fatal':

        all_dockle_high = DockleScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('dockle_fatal'))

        for key, value in all_dockle_high.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    elif query == 'info':
        all_dockle_medium = DockleScanDb.objects.filter(project__uu_id=project_id). \
            aggregate(Sum('dockle_info'))

        for key, value in all_dockle_medium.items():
            if value is None:
                all_dockle = '0'
            else:
                all_dockle = value

    return all_dockle


def all_vuln_count(project_id, query):
    all_data = 0
    if query == 'High':
        web_all_high = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                       severity='High',
                                                       )

        sast_all_high = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                           severity='High'
                                                           )

        net_all_high = NetworkScanResultsDb.objects.filter(severity='High',
                                                           project__uu_id=project_id
                                                           )

        pentest_all_high = PentestScanResultsDb.objects.filter(severity='High',
                                                               project__uu_id=project_id
                                                               )
        all_data = chain(web_all_high,
                         sast_all_high,
                         net_all_high,
                         pentest_all_high,
                         )

    elif query == 'Medium':
        web_all_medium = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                         severity='Medium',
                                                         )

        sast_all_medium = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                             severity='Medium'
                                                             )

        net_all_medium = NetworkScanResultsDb.objects.filter(severity='Medium',
                                                             project__uu_id=project_id
                                                             )

        pentest_all_medium = PentestScanResultsDb.objects.filter(severity='Medium',
                                                                 project__uu_id=project_id
                                                                 )

        all_data = chain(web_all_medium,
                         sast_all_medium,
                         net_all_medium,
                         pentest_all_medium,
                         )

    elif query == 'Low':

        web_all_low = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                      severity='Low',
                                                      )

        sast_all_low = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                          severity='Low'
                                                          )

        net_all_low = NetworkScanResultsDb.objects.filter(severity='Low',
                                                          project__uu_id=project_id
                                                          )

        pentest_all_low = PentestScanResultsDb.objects.filter(severity='Low',
                                                              project__uu_id=project_id
                                                              )

        all_data = chain(web_all_low,
                         sast_all_low,
                         net_all_low,
                         pentest_all_low,
                         )

    elif query == 'Total':
        web_all = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                  )

        sast_all = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                      )

        net_all = NetworkScanResultsDb.objects.filter(project__uu_id=project_id
                                                      )

        pentest_all = PentestScanResultsDb.objects.filter(project__uu_id=project_id
                                                          )

        all_data = chain(web_all,
                         sast_all,
                         net_all,
                         pentest_all,
                         )

    elif query == 'False':
        web_all_false = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                        false_positive='Yes')

        sast_all_false = StaticScanResultsDb.objects.filter(
            project__uu_id=project_id,
            false_positive='Yes')

        net_all_false = NetworkScanResultsDb.objects.filter(project__uu_id=project_id,
                                                            false_positive='Yes')
        all_data = chain(web_all_false,
                         sast_all_false,
                         net_all_false,
                         )

    elif query == 'Close':
        web_all_close = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                        vuln_status='Closed')

        sast_all_close = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                            vuln_status='Closed')

        net_all_close = NetworkScanResultsDb.objects.filter(project__uu_id=project_id,
                                                            vuln_status='Closed')
        all_data = chain(web_all_close,
                         sast_all_close,
                         net_all_close,
                         )

    elif query == 'Open':

        web_all_open = WebScanResultsDb.objects.filter(project__uu_id=project_id,
                                                       vuln_status='Open')

        sast_all_open = StaticScanResultsDb.objects.filter(project__uu_id=project_id,
                                                           vuln_status='Open')

        net_all_open = NetworkScanResultsDb.objects.filter(project__uu_id=project_id,
                                                           vuln_status='Open')
        all_data = chain(web_all_open,
                         sast_all_open,
                         net_all_open,
                         )

    return all_data


def all_vuln_count_data(project_id, query):
    all_data = 0

    if query == 'false':
        web_false_positive = WebScanResultsDb.objects.filter(false_positive='Yes',
                                                             project__uu_id=project_id)

        sast_false_positive = StaticScanResultsDb.objects.filter(
            false_positive='Yes',
            project__uu_id=project_id)

        net_false_positive = NetworkScanResultsDb.objects.filter(false_positive='Yes',
                                                                 project__uu_id=project_id)

        all_data = int(len(web_false_positive)) + \
                   int(len(sast_false_positive)) + \
                   int(len(net_false_positive))

    elif query == 'Closed':
        web_closed_vuln = WebScanResultsDb.objects.filter(vuln_status='Closed',
                                                          project__uu_id=project_id)

        net_closed_vuln = NetworkScanResultsDb.objects.filter(vuln_status='Closed',
                                                              project__uu_id=project_id)

        sast_closed_vuln = StaticScanResultsDb.objects.filter(vuln_status='Closed',
                                                              project__uu_id=project_id)

        pentest_closed_vuln = PentestScanResultsDb.objects.filter(vuln_status='Closed',
                                                                  project__uu_id=project_id)
        all_data = int(len(web_closed_vuln)) + \
                   int(len(net_closed_vuln)) + \
                   int(len(sast_closed_vuln)) + \
                   int(len(pentest_closed_vuln))


    elif query == 'Open':
        web_open_vuln = WebScanResultsDb.objects.filter(vuln_status='Open',
                                                        project__uu_id=project_id)
        net_open_vuln = NetworkScanResultsDb.objects.filter(vuln_status='Open',
                                                            project__uu_id=project_id)
        sast_open_vuln = StaticScanResultsDb.objects.filter(vuln_status='Open',
                                                            project__uu_id=project_id)

        pentest_open_vuln = PentestScanResultsDb.objects.filter(vuln_status='Open',
                                                                project__uu_id=project_id)
        # add your scanner name here <scannername>
        all_data = int(len(web_open_vuln)) + \
                   int(len(net_open_vuln)) + \
                   int(len(sast_open_vuln)) + \
                   int(len(pentest_open_vuln))

    return all_data
