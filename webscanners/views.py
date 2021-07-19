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

from __future__ import unicode_literals

import hashlib
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.models import Notification

from jiraticketing.models import jirasetting
from webscanners.models import (WebScanResultsDb, WebScansDb)


def list_vuln(request):
    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        scanner = request.GET["scanner"]
    else:
        scan_id = None
        scanner = None

    all_vuln = WebScanResultsDb.objects.filter(scan_id=scan_id, scanner=scanner)

    return render(
        request,
        "webscanners/scans/list_vuln.html",
        {
            "all_vuln": all_vuln,
            "scan_id": scan_id,
        },
    )


def list_scans(request):
    scan_list = WebScansDb.objects.filter()

    all_notify = Notification.objects.unread()

    return render(request, "webscanners/scans/list_scans.html", {"all_scans": scan_list, "message": all_notify})


def list_vuln_info(request):
    scan_id = None
    name = None
    scanner = None
    jira_url = None

    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        name = request.GET["scan_name"]
        scanner = request.GET['scanner']
    if request.method == "POST":
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        vuln_name = request.POST.get("vuln_name")
        scanner = request.POST.get("scanner")
        WebScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id, scanner=scanner
        ).update(false_positive=false_positive, vuln_status=status)

        if false_positive == "Yes":
            vuln_info = WebScanResultsDb.objects.filter(scan_id=scan_id, vuln_id=vuln_id, scanner=scanner
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.url
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                WebScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id, scanner=scanner
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                )

        all_vuln = WebScanResultsDb.objects.filter(scan_id=scan_id, false_positive="No", vuln_status="Open", scanner=scanner
        )

        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info

        WebScansDb.objects.filter(scan_id=scan_id, scanner=scanner).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln_info") + "?scan_id=%s&scan_name=%s&scanner=%s" % (
            scan_id, vuln_name, scanner)
        )

    vuln_data = WebScanResultsDb.objects.filter(
        title=name,
        scan_id=scan_id,
        scanner=scanner
    )

    return render(request, "webscanners/scans/list_vuln_info.html", {"vuln_data": vuln_data, "jira_url": jira_url})


def scan_details(request):
    if request.method == "GET":
        vuln_id = request.GET["vuln_id"]
        scanner = request.GET["scanner"]
    else:
        vuln_id = ""
        scanner = ""
    vul_dat = WebScanResultsDb.objects.filter(vuln_id=vuln_id, scanner=scanner
    ).order_by("vuln_id")

    return render(request, "webscanners/scans/vuln_details.html", {"vul_dat": vul_dat})


def scan_delete(request):
    if request.method == "POST":
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = WebScansDb.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = WebScanResultsDb.objects.filter(scan_id=scan_id
            )
            item_results.delete()
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


def vuln_delete(request):
    if request.method == "POST":
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = WebScanResultsDb.objects.filter(scanner=scanner, vuln_id=vuln_id
            )
            delete_vuln.delete()
        all_vuln = WebScanResultsDb.objects.filter(scanner=scanner, scan_id=scan_id
        )

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Information"))

        WebScansDb.objects.filter(scan_id=scan_id, scanner=scanner).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln") + "?scan_id=%s&scanner=%s" % (scan_id, scanner)
        )
