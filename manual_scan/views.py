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

import uuid
from datetime import datetime

from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse

from manual_scan.models import (VulnerabilityData, ManualScanResultsDb,
                                ManualScansDb)
from projects.models import ProjectDb

from .forms import *


def list_scan(request):
    """

    :param request:
    :return:
    """
    all_scans = ManualScansDb.objects.all()

    return render(request, "pentest/list_scan.html", {"all_scans": all_scans})


def add_list_scan(request):
    """

    :param request:
    :return:
    """
    all_projects = ProjectDb.objects.all()

    if request.method == "POST":
        scan_url = request.POST.get("scan_url")
        project_id = request.POST.get("project_id")
        pentest_type = request.POST.get("pentest_type")
        date_time = datetime.now()
        scanid = uuid.uuid4()

        dump_scan = ManualScansDb(
            date_time=date_time,
            scan_url=scan_url,
            scan_id=scanid,
            pentest_type=pentest_type,
            project_id=project_id,
        )
        dump_scan.save()

        messages.success(request, "Target Added")

        return HttpResponseRedirect(reverse("manual_scan:list_scan"))

    return render(request, "pentest/add_list_scan.html", {"all_projects": all_projects})


def vuln_list(request):
    """

    :param request:
    :return:
    """
    all_vuln = None
    scan_id = None
    vuln_id = None
    project_id = None

    vuln_data = VulnerabilityData.objects.all()

    for vul in vuln_data:
        vuln_id = vul.vuln_data_id

    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        project_id = request.GET["project_id"]
        all_vuln = ManualScanResultsDb.objects.filter(scan_id=scan_id
        )

    return render(
        request,
        "pentest/manual_vuln_list.html",
        {
            "all_vuln": all_vuln,
            "scan_id": scan_id,
            "vuln_data": vuln_id,
            "project_id": project_id,
        },
    )


def add_vuln(request):
    """

    :param request:
    :return:
    """
    scanid = None
    severity_color = None
    project_id = None
    uploaded_poc_url = ''

    if request.method == "GET":
        scanid = request.GET["scan_id"]
        project_id = request.GET["project_id"]

    if request.method == "POST":
        vuln_name = request.POST.get("vuln_name")
        severity = request.POST.get("vuln_severity")
        vuln_url = request.POST.get("vuln_instance")
        description = request.POST.get("vuln_description")
        solution = request.POST.get("vuln_solution")
        reference = request.POST.get("vuln_reference")
        scan_id = request.POST.get("scan_id")
        project_id = request.POST.get("project_id")
        pentest_type = request.POST.get("pentest_type")
        poc = request.FILES.get('poc', False)
        poc_description = request.POST.get("poc_description")
        date_time = datetime.now()
        vuln_id = uuid.uuid4()

        fs = FileSystemStorage()
        if poc is not False:
            filename = fs.save(poc.name, poc)
            uploaded_poc_url = fs.url(filename)

        if severity == "High":
            severity_color = "danger"

        elif severity == "Medium":
            severity_color = "warning"

        elif severity == "Low":
            severity_color = "info"

        dump_data = ManualScanResultsDb(
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            severity_color=severity_color,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            reference=reference,
            scan_id=scan_id,
            pentest_type=pentest_type,
            vuln_status="Open",
            project_id=project_id,
            Poc_Img=uploaded_poc_url,
            poc_description=poc_description,
        )
        dump_data.save()

        all_scan_data = ManualScanResultsDb.objects.filter(
            scan_id=scan_id
        )

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        ManualScansDb.objects.filter(scan_id=scan_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
        )

        return HttpResponseRedirect(reverse("manual_scan:list_scan"))

    return render(request, "pentest/add_manual_vuln.html", {"scanid": scanid})


def vuln_details(request):
    """

    :param request:
    :return:
    """

    if request.method == "GET":
        vuln_id = request.GET["vuln_id"]

        vuln_detail = ManualScanResultsDb.objects.filter(
            vuln_id=vuln_id
        )

    return render(request, "pentest/manual_vuln_data.html", {"vuln_detail": vuln_detail})


def edit_vuln(request):
    """

    :param request:
    :return:
    """

    severity_color = None
    project_id = None
    vuln_id = None
    if request.method == "GET":
        vuln_id = request.GET["vuln_id"]
        project_id = request.GET["project_id"]

    vuln_data = ManualScanResultsDb.objects.filter(vuln_id=vuln_id
    )

    if request.method == "POST":
        vuln_id = request.POST.get("vuln_id")
        project_id = request.POST.get("project_id")
        vuln_name = request.POST.get("vuln_name")
        severity = request.POST.get("vuln_severity")
        vuln_url = request.POST.get("vuln_instance")
        description = request.POST.get("vuln_description")
        solution = request.POST.get("vuln_solution")
        reference = request.POST.get("vuln_reference")
        scan_id = request.POST.get("scan_id")
        date_time = datetime.now()

        if severity == "High":
            severity_color = "danger"

        elif severity == "Medium":
            severity_color = "warning"

        elif severity == "Low":
            severity_color = "info"

        ManualScanResultsDb.objects.filter(vuln_id=vuln_id
        ).update(
            vuln_name=vuln_name,
            severity=severity,
            vuln_url=vuln_url,
            description=description,
            solution=solution,
            reference=reference,
            severity_color=severity_color,
        )
        all_scan_data = ManualScanResultsDb.objects.filter(scan_id=scan_id
        )

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        ManualScansDb.objects.filter(scan_id=scan_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
        )
        return HttpResponseRedirect(
            reverse("manual_scan:vuln_list")
            + "?scan_id=%(scan_id)s&project_id=%(project_id)s"
            % {"scan_id": scan_id, "project_id": project_id}
        )

    return render(
        request,
        "pentest/edit_vuln.html",
        {"vuln_data": vuln_data, "vuln_id": vuln_id, "project_id": project_id},
    )


def manual_vuln_data(request):

    if request.method == "POST":
        vuln_id = request.POST.get("vuln_id")
        status = request.POST.get("status")
        scan_id = request.POST.get("scan_id")
        project_id = request.POST.get("project_id")
        date_time = datetime.now()

        ManualScanResultsDb.objects.filter(vuln_id=vuln_id
        ).update(
            vuln_status=status,
            date_time=date_time,
        )
        all_scan_data = ManualScanResultsDb.objects.filter(scan_id=scan_id, vuln_status="Open"
        )

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        ManualScansDb.objects.filter(scan_id=scan_id).update(
            date_time=date_time,
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low
        )

    return HttpResponseRedirect(
        reverse("manual_scan:vuln_list")
        + "?scan_id=%(scan_id)s&project_id=%(project_id)s"
        % {"scan_id": scan_id, "project_id": project_id}
    )


def del_vuln(request):
    """

    :param request:
    :return:
    """

    if request.method == "POST":
        scan_id = request.POST.get("scan_id")
        get_vuln_id = request.POST.get("vuln_id")
        project_id = request.POST.get("project_id")

        scan_item = str(get_vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            del_vuln = ManualScanResultsDb.objects.filter(vuln_id=vuln_id
            )
            del_vuln.delete()

        all_scan_data = ManualScanResultsDb.objects.filter(scan_id=scan_id
        )

        total_vuln = len(all_scan_data)
        total_high = len(all_scan_data.filter(severity="High"))
        total_medium = len(all_scan_data.filter(severity="Medium"))
        total_low = len(all_scan_data.filter(severity="Low"))

        ManualScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vuln,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
        )

        return HttpResponseRedirect(
            reverse("manual_scan:vuln_list")
            + "?scan_id=%s&project_id=%s" % (scan_id, project_id)
        )


def del_scan(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        get_scan_id = request.POST.get("scan_id")

        scan_item = str(get_scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            del_scan = ManualScanResultsDb.objects.filter(
               scan_id=scan_id
            )
            del_scan.delete()

            del_scan_info = ManualScansDb.objects.filter(
               scan_id=scan_id
            )
            del_scan_info.delete()

            messages.warning(request, "Target Deleted")

        return HttpResponseRedirect(reverse("manual_scan:list_scan"))


def add_vuln_data(request):
    """

    :param request:
    :return:
    """

    if request.method == "POST":
        vuln_data_id = uuid.uuid4()
        vuln_name = request.POST.get("vuln_name")
        vuln_description = request.POST.get("vuln_description")
        vuln_severity = request.POST.get("vuln_severity")
        vuln_remediation = request.POST.get("vuln_remediation")
        vuln_references = request.POST.get("vuln_references")

        dump_data = VulnerabilityData(
            vuln_data_id=vuln_data_id,
            vuln_name=vuln_name,
            vuln_description=vuln_description,
            vuln_severity=vuln_severity,
            vuln_remediation=vuln_remediation,
            vuln_references=vuln_references,

        )
        dump_data.save()

        return HttpResponseRedirect(reverse("manual_scan:list_scan"))
    return render(request, "pentest/manual_vuln_data.html")


def add_new_vuln(request):
    """

    :param request:
    :return:
    """
    all_vuln_data = VulnerabilityData.objects.all()
    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        vuln_id = request.GET["vuln_id"]
        project_id = request.GET["project_id"]

        all_vuln = ManualScanResultsDb.objects.filter(scan_id=scan_id
        )
        vuln_data = VulnerabilityData.objects.filter(vuln_data_id=vuln_id
        )

    return render(
        request,
        "pentest/add_vulnerability.html",
        {
            "all_vuln": all_vuln,
            "vuln_data": vuln_data,
            "all_vuln_data": all_vuln_data,
            "scan_id": scan_id,
            "project_id": project_id,
        },
    )
