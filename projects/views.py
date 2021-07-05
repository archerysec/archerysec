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

import datetime
import uuid
from itertools import chain

from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse

from compliance.models import (dockle_scan_db, dockle_scan_results_db,
                               inspec_scan_db, inspec_scan_results_db)
from dashboard.scans_data import scans_query
from manual_scan.models import manual_scan_results_db, manual_scans_db
from projects.models import month_db, project_db, project_scan_db
from staticscanners.models import (StaticScansDb, StaticScanResultsDb)
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb)

project_dat = None


def create_form(request):
    return render(request, "projects/project_create.html")


def create(request):
    if request.method == "POST":
        username = request.user.username
        project_id = uuid.uuid4()
        project_name = request.POST.get(
            "projectname",
        )
        project_date = request.POST.get(
            "projectstart",
        )
        project_end = request.POST.get(
            "projectend",
        )
        project_owner = request.POST.get(
            "projectowner",
        )
        project_disc = request.POST.get(
            "project_disc",
        )
        date_time = datetime.datetime.now()

        save_project = project_db(
            username=username,
            project_name=project_name,
            project_id=project_id,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc,
            date_time=date_time,
            total_vuln=0,
            total_high=0,
            total_medium=0,
            total_low=0,
            total_open=0,
            total_false=0,
            total_close=0,
            total_net=0,
            total_web=0,
            total_static=0,
            high_net=0,
            high_web=0,
            high_static=0,
            medium_net=0,
            medium_web=0,
            medium_static=0,
            low_net=0,
            low_web=0,
            low_static=0,
        )
        save_project.save()

        messages.success(request, "Project Created")
        all_month_data_display = month_db.objects.filter(username=username)

        if len(all_month_data_display) == 0:
            save_months_data = month_db(
                username=username,
                project_id=project_id,
                month=datetime.datetime.now().month,
                high=0,
                medium=0,
                low=0,
            )
            save_months_data.save()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))

    return render(request, "dashboard/project.html")


def projects(request):

    if request.method == "POST":
        project_id = request.POST.get(
            "proj_id",
        )

        del_proj = project_db.objects.filter(project_id=project_id)
        del_proj.delete()

        web_scans = WebScansDb.objects.filter(project_id=project_id)
        web_scans.delete()

        web_scans_result = WebScanResultsDb.objects.filter(project_id=project_id)
        web_scans_result.delete()

        sast_scans = StaticScansDb.objects.filter(project_id=project_id)
        sast_scans.delete()

        sast_scans_result = StaticScanResultsDb.objects.filter(project_id=project_id)
        sast_scans_result.delete()

        net_scans = NetworkScanDb.objects.filter(project_id=project_id)
        net_scans.delete()

        net_scans_result = NetworkScanResultsDb.objects.filter(project_id=project_id)
        net_scans_result.delete()

        inspec = inspec_scan_db.objects.filter(project_id=project_id)
        inspec.delete()
        inspec_result = inspec_scan_results_db.objects.filter(project_id=project_id)
        inspec_result.delete()

        dockle = dockle_scan_db.objects.filter(project_id=project_id)
        dockle.delete()
        dockle_result = dockle_scan_results_db.objects.filter(project_id=project_id)
        dockle_result.delete()

        openvas = openvas_scan_db.objects.filter(project_id=project_id)
        openvas.delete()
        openvas_result = ov_scan_result_db.objects.filter(project_id=project_id)
        openvas_result.delete()

        nessus = NetworkScanDb.objects.filter(project_id=project_id)
        nessus.delete()

        nessus_result = NetworkScanDb.objects.filter(project_id=project_id)
        nessus_result.delete()

        nessus_scan_results = NetworkScanResultsDb.objects.filter(
            project_id=project_id
        )
        nessus_scan_results.delete()

        pentest = manual_scan_results_db.objects.filter(project_id=project_id)
        pentest.delete()

        pentest_dat = manual_scans_db.objects.filter(project_id=project_id)
        pentest_dat.delete()

        month_db_del = month_db.objects.filter(project_id=project_id)
        month_db_del.delete()

        messages.warning(request, "Project Deleted")

        return HttpResponseRedirect(reverse("dashboard:dashboard"))

    return render(request, "dashboard/project.html", {"all_projects": all_projects})


def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == "GET":
        project_id = request.GET["project_id"]
        username = request.user.username
        project_dat = project_db.objects.filter(
            project_id=project_id, username=username
        )

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")
        project_disc = request.POST.get("project_disc")

        project_db.objects.filter(project_id=project_id).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc,
        )
        return HttpResponseRedirect(
            reverse("projects:projects") + "?proj_id=%s" % project_id
        )
    return render(request, "projects/project_edit.html", {"project_dat": project_dat})
