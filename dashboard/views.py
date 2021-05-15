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

import datetime
from itertools import chain

from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User
from django.db.models import Sum
from django.shortcuts import HttpResponse, HttpResponseRedirect, render
from django.urls import reverse
from notifications.models import Notification

from compliance.models import dockle_scan_db, inspec_scan_db
from dashboard.scans_data import scans_query
# Add Pentest db
from manual_scan.models import manual_scan_results_db, manual_scans_db
# Network Scanners db models
from networkscanners.models import (nessus_report_db, nessus_scan_db,
                                    nessus_scan_results_db, openvas_scan_db,
                                    ov_scan_result_db)
from projects.models import Month, MonthSqlite, month_db, project_db
# Add Static Scanners db models
from staticscanners.models import (StaticScanResultsDb, StaticScansDb)
# Add your Web scanner db
from webscanners.models import (WebScanResultsDb, WebScansDb)
from webscanners.resources import AllResource

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def trend_update(username):
    current_month = ""

    all_project = project_db.objects.filter(username=username)

    for project in all_project:
        proj_id = project.project_id
        all_date_data = (
            project_db.objects.annotate(month=Month("date_time"))
            .values("month")
            .annotate(total_high=Sum("total_high"))
            .annotate(total_medium=Sum("total_medium"))
            .annotate(total_low=Sum("total_low"))
            .order_by("month")
        )

        try:
            high = all_date_data.first()["total_high"]
            medium = all_date_data.first()["total_medium"]
            low = all_date_data.first()["total_low"]
        except:
            all_date_data = (
                project_db.objects.annotate(month=MonthSqlite("date_time"))
                .values("month")
                .annotate(total_high=Sum("total_high"))
                .annotate(total_medium=Sum("total_medium"))
                .annotate(total_low=Sum("total_low"))
                .order_by("month")
            )
            high = all_date_data.first()["total_high"]
            medium = all_date_data.first()["total_medium"]
            low = all_date_data.first()["total_low"]

        all_month_data_display = month_db.objects.filter(username=username)

        if len(all_month_data_display) == 0:
            add_data = month_db(
                username=username,
                project_id=proj_id,
                month=current_month,
                high=high,
                medium=medium,
                low=low,
            )
            add_data.save()

        for data in all_month_data_display:
            current_month = datetime.datetime.now().month
            if int(current_month) == 1:
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="2"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="3"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="4"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="5"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="6"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="7"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="8"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="9"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="10"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="11"
                ).delete()
                month_db.objects.filter(
                    username=username, project_id=proj_id, month="12"
                ).delete()

            match_data = month_db.objects.filter(
                username=username, project_id=proj_id, month=current_month
            )
            if len(match_data) == 0:
                add_data = month_db(
                    username=username,
                    project_id=proj_id,
                    month=current_month,
                    high=high,
                    medium=medium,
                    low=low,
                )
                add_data.save()

            elif int(data.month) == int(current_month):
                month_db.objects.filter(
                    username=username, project_id=proj_id, month=current_month
                ).update(high=high, medium=medium, low=low)

        total_vuln = scans_query.all_vuln(
            username=username, project_id=proj_id, query="total"
        )
        total_high = scans_query.all_vuln(
            username=username, project_id=proj_id, query="high"
        )
        total_medium = scans_query.all_vuln(
            username=username, project_id=proj_id, query="medium"
        )
        total_low = scans_query.all_vuln(
            username=username, project_id=proj_id, query="low"
        )

        total_open = scans_query.all_vuln_count_data(username, proj_id, query="Open")
        total_close = scans_query.all_vuln_count_data(username, proj_id, query="Closed")
        total_false = scans_query.all_vuln_count_data(username, proj_id, query="false")

        total_net = scans_query.all_net(username, proj_id, query="total")
        total_web = scans_query.all_web(username, proj_id, query="total")
        total_static = scans_query.all_static(username, proj_id, query="total")

        high_net = scans_query.all_net(username, proj_id, query="high")
        high_web = scans_query.all_web(username, proj_id, query="high")
        high_static = scans_query.all_static(username, proj_id, query="high")

        medium_net = scans_query.all_net(username, proj_id, query="medium")
        medium_web = scans_query.all_web(username, proj_id, query="medium")
        medium_static = scans_query.all_static(username, proj_id, query="medium")

        low_net = scans_query.all_net(username, proj_id, query="low")
        low_web = scans_query.all_web(username, proj_id, query="low")
        low_static = scans_query.all_static(username, proj_id, query="low")

        project_db.objects.filter(username=username, project_id=proj_id).update(
            total_vuln=total_vuln,
            total_open=total_open,
            total_close=total_close,
            total_false=total_false,
            total_net=total_net,
            total_web=total_web,
            total_static=total_static,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            high_net=high_net,
            high_web=high_web,
            high_static=high_static,
            medium_net=medium_net,
            medium_web=medium_web,
            medium_static=medium_static,
            low_net=low_net,
            low_web=low_web,
            low_static=low_static,
        )


def dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = "vscanners"
    username = request.user.username

    trend_update(username=username)

    all_project = project_db.objects.filter(username=username)

    current_year = datetime.datetime.now().year

    user = user_logged_in
    all_notify = Notification.objects.unread()

    all_month_data_display = (
        month_db.objects.filter(username=username)
        .values("month", "high", "medium", "low")
        .distinct()
    )

    return render(
        request,
        "dashboard/index.html",
        {
            "all_project": all_project,
            "scanners": scanners,
            "total_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_vuln")),
            "open_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_open")),
            "close_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_close")),
            "false_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_false")),
            "net_count_project": project_db.objects.filter(username=username).aggregate(
                Sum("total_net")
            ),
            "web_count_project": project_db.objects.filter(username=username).aggregate(
                Sum("total_web")
            ),
            "static_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_static")),
            "high_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_high")),
            "medium_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("total_medium")),
            "low_count_project": project_db.objects.filter(username=username).aggregate(
                Sum("total_low")
            ),
            "high_net_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("high_net")),
            "high_web_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("high_web")),
            "high_static_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("high_static")),
            "medium_net_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("medium_net")),
            "medium_web_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("medium_web")),
            "medium_static_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("medium_static")),
            "low_net_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("low_net")),
            "low_web_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("low_web")),
            "low_static_count_project": project_db.objects.filter(
                username=username
            ).aggregate(Sum("low_static")),
            "all_month_data_display": all_month_data_display,
            "current_year": current_year,
            "message": all_notify,
        },
    )


def project_dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = "vscanners"
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(
        request,
        "dashboard/project.html",
        {"all_project": all_project, "scanners": scanners, "message": all_notify},
    )


def proj_data(request):
    """
    The function pulling all project data from database.
    :param request:
    :return:
    """
    username = request.user.username
    all_project = project_db.objects.filter(username=username)
    if request.GET["project_id"]:
        project_id = request.GET["project_id"]
    else:
        project_id = ""

    project_dat = project_db.objects.filter(username=username, project_id=project_id)

    # Web scanners project data <scannername>
    burp = WebScansDb.objects.filter(username=username, scanner='Burp', project_id=project_id)
    zap = WebScansDb.objects.filter(
        username=username, project_id=project_id, scanner="zap"
    )
    arachni = WebScansDb.objects.filter(username=username, project_id=project_id, scanner="Arachni")
    webinspect = WebScansDb.objects.filter(
        username=username, project_id=project_id, scanner="Webinspect"
    )
    netsparker = WebScansDb.objects.filter(
        username=username, project_id=project_id, scanner="Netsparker"
    )
    acunetix = WebScansDb.objects.filter(username=username, project_id=project_id, scanner="Acunetix")

    # Static scanners project data <scannername>
    dependency_check = dependencycheck_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    findbugs = findbugs_scan_db.objects.filter(username=username, project_id=project_id)
    clair = clair_scan_db.objects.filter(username=username, project_id=project_id)
    trivy = trivy_scan_db.objects.filter(username=username, project_id=project_id)
    gitlabsast = gitlabsast_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    gitlabcontainerscan = gitlabcontainerscan_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    gitlabsca = gitlabsca_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    npmaudit = npmaudit_scan_db.objects.filter(username=username, project_id=project_id)
    nodejsscan = nodejsscan_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    semgrepscan = semgrepscan_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    tfsec = tfsec_scan_db.objects.filter(username=username, project_id=project_id)
    whitesource = whitesource_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    checkmarx = checkmarx_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    bandit = bandit_scan_db.objects.filter(username=username, project_id=project_id)
    twistlock = twistlock_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    brakeman = brakeman_scan_db.objects.filter(username=username, project_id=project_id)

    web_scan_dat = chain(burp, zap, arachni, webinspect, netsparker, acunetix)

    # add you scanner into chain <scannername>
    static_scan = chain(
        dependency_check,
        findbugs,
        clair,
        trivy,
        gitlabsast,
        gitlabcontainerscan,
        gitlabsca,
        npmaudit,
        nodejsscan,
        semgrepscan,
        tfsec,
        whitesource,
        checkmarx,
        bandit,
        twistlock,
        brakeman,
    )

    openvas_dat = openvas_scan_db.objects.filter(
        username=username, project_id=project_id
    )
    nessus_dat = nessus_scan_db.objects.filter(username=username, project_id=project_id)

    network_dat = chain(openvas_dat, nessus_dat)

    inspec_dat = inspec_scan_db.objects.filter(username=username, project_id=project_id)

    dockle_dat = dockle_scan_db.objects.filter(username=username, project_id=project_id)

    compliance_dat = chain(inspec_dat, dockle_dat)

    all_comp_inspec = inspec_scan_db.objects.filter(
        username=username, project_id=project_id
    )

    all_comp_dockle = inspec_scan_db.objects.filter(
        username=username, project_id=project_id
    )

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = manual_scans_db.objects.filter(username=username, project_id=project_id)

    all_notify = Notification.objects.unread()

    all_high = scans_query.all_vuln(
        username=username, project_id=project_id, query="high"
    )
    all_medium = scans_query.all_vuln(
        username=username, project_id=project_id, query="medium"
    )
    all_low = scans_query.all_vuln(
        username=username, project_id=project_id, query="low"
    )

    total = all_high, all_medium, all_low

    tota_vuln = sum(total)

    # add your scanner into render <scannername>

    return render(
        request,
        "dashboard/project.html",
        {
            "project_id": project_id,
            "tota_vuln": tota_vuln,
            "all_vuln": scans_query.all_vuln(
                username=username, project_id=project_id, query="total"
            ),
            "total_web": scans_query.all_web(
                username=username, project_id=project_id, query="total"
            ),
            "total_static": scans_query.all_static(
                username=username, project_id=project_id, query="total"
            ),
            "total_network": scans_query.all_net(
                username=username, project_id=project_id, query="total"
            ),
            "all_high": all_high,
            "all_medium": all_medium,
            "all_low": all_low,
            "all_web_high": scans_query.all_web(
                username=username, project_id=project_id, query="high"
            ),
            "all_web_medium": scans_query.all_web(
                username=username, project_id=project_id, query="medium"
            ),
            "all_network_medium": scans_query.all_net(
                username=username, project_id=project_id, query="medium"
            ),
            "all_network_high": scans_query.all_net(
                username=username, project_id=project_id, query="high"
            ),
            "all_web_low": scans_query.all_web(
                username=username, project_id=project_id, query="low"
            ),
            "all_network_low": scans_query.all_net(
                username=username, project_id=project_id, query="low"
            ),
            "all_project": all_project,
            "project_dat": project_dat,
            "web_scan_dat": web_scan_dat,
            "all_static_high": scans_query.all_static(
                username=username, project_id=project_id, query="high"
            ),
            "all_static_medium": scans_query.all_static(
                username=username, project_id=project_id, query="medium"
            ),
            "all_static_low": scans_query.all_static(
                username=username, project_id=project_id, query="low"
            ),
            "static_scan": static_scan,
            "zap": zap,
            "burp": burp,
            "arachni": arachni,
            "webinspect": webinspect,
            "netsparker": netsparker,
            "acunetix": acunetix,
            "dependency_check": dependency_check,
            "findbugs": findbugs,
            "bandit": bandit,
            "clair": clair,
            "trivy": trivy,
            "gitlabsast": gitlabsast,
            "twistlock": twistlock,
            "brakeman": brakeman,
            "gitlabcontainerscan": gitlabcontainerscan,
            "gitlabsca": gitlabsca,
            "npmaudit": npmaudit,
            "nodejsscan": nodejsscan,
            "semgrepscan": semgrepscan,
            "tfsec": tfsec,
            "whitesource": whitesource,
            "checkmarx": checkmarx,
            "pentest": pentest,
            "network_dat": network_dat,
            "all_zap_scan": int(
                scans_query.all_zap(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_burp_scan": int(
                scans_query.all_burp(
                    username=username, project_id=project_id, query="total"
                )
            ),
            # add your scanner name <scannername>
            "all_arachni_scan": int(
                scans_query.all_arachni(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_acunetix_scan": int(
                scans_query.all_acunetix(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_netsparker_scan": int(
                scans_query.all_netsparker(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_openvas_scan": int(
                scans_query.all_openvas(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_nessus_scan": int(
                scans_query.all_nessus(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_dependency_scan": int(
                scans_query.all_dependency(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_findbugs_scan": int(
                scans_query.all_findbugs(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_clair_scan": int(
                scans_query.all_clair(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_trivy_scan": int(
                scans_query.all_trivy(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_gitlabsast_scan": int(
                scans_query.all_gitlabsast(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_twistlock_scan": int(
                scans_query.all_twistlock(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_brakeman_scan": int(
                scans_query.all_brakeman(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_gitlabcontainerscan_scan": int(
                scans_query.all_gitlabcontainerscan(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_gitlabsca_scan": int(
                scans_query.all_gitlabsca(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_npmaudit_scan": int(
                scans_query.all_npmaudit(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_nodejsscan_scan": int(
                scans_query.all_nodejsscan(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_semgrepscan_scan": int(
                scans_query.all_semgrepscan(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_tfsec_scan": int(
                scans_query.all_tfsec(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_whitesource_scan": int(
                scans_query.all_whitesource(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_checkmarx_scan": int(
                scans_query.all_checkmarx(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_webinspect_scan": int(
                scans_query.all_webinspect(
                    username=username, project_id=project_id, query="total"
                )
            ),
            "all_compliance_failed": scans_query.all_compliance(
                username=username, project_id=project_id, query="failed"
            ),
            "all_compliance_passed": scans_query.all_compliance(
                username=username, project_id=project_id, query="passed"
            ),
            "all_compliance_skipped": scans_query.all_compliance(
                username=username, project_id=project_id, query="skipped"
            ),
            "total_compliance": scans_query.all_compliance(
                username=username, project_id=project_id, query="total"
            ),
            "openvas_dat": openvas_dat,
            "nessus_dat": nessus_dat,
            "all_compliance": all_compliance_seg,
            "compliance_dat": compliance_dat,
            "inspec_dat": inspec_dat,
            "dockle_dat": dockle_dat,
            "all_zap_high": WebScansDb.objects.filter(
                scanner="zap", username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_zap_low": WebScansDb.objects.filter(
                scanner="zap", username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_zap_medium": WebScansDb.objects.filter(
                scanner="zap", username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_webinspect_high": WebScansDb.objects.filter(
                scanner="Webinspect", username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_webinspect_low": WebScansDb.objects.filter(
                scanner="Webinspect", username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_webinspect_medium": WebScansDb.objects.filter(
                scanner="Webinspect", username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_acunetix_high": WebScansDb.objects.filter(
                scanner="Acunetix", username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_acunetix_low": WebScansDb.objects.filter(
                scanner="Acunetix", username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_acunetix_medium": WebScansDb.objects.filter(
                scanner="Acunetix", username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_burp_high": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Burp'
            ).aggregate(Sum("high_vul")),
            "all_burp_low": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Burp'
            ).aggregate(Sum("low_vul")),
            "all_burp_medium": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Burp'
            ).aggregate(Sum("medium_vul")),
            "all_arachni_high": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Arachni'
            ).aggregate(Sum("high_vul")),
            "all_arachni_low": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Arachni'
            ).aggregate(Sum("low_vul")),
            "all_arachni_medium": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Arachni'
            ).aggregate(Sum("medium_vul")),
            "all_netsparker_high": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Netsparker'
            ).aggregate(Sum("high_vul")),
            "all_netsparker_low": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Netsparker'
            ).aggregate(Sum("low_vul")),
            "all_netsparker_medium": WebScansDb.objects.filter(
                username=username, project_id=project_id, scanner='Netsparker'
            ).aggregate(Sum("medium_vul")),
            "all_openvas_high": openvas_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_openvas_low": openvas_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_openvas_medium": openvas_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_nessus_high": nessus_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("total_high")),
            "all_nessus_low": nessus_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("total_low")),
            "all_nessus_medium": nessus_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("total_medium")),
            "all_dependency_high": dependencycheck_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_dependency_low": dependencycheck_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_dependency_medium": dependencycheck_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_findbugs_high": findbugs_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_findbugs_low": findbugs_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_findbugs_medium": findbugs_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_bandit_high": bandit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_bandit_low": bandit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_bandit_medium": bandit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_clair_high": clair_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_clair_low": clair_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_clair_medium": clair_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_trivy_high": trivy_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_trivy_low": trivy_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_trivy_medium": trivy_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            # add your scanner accrodingly <scannername>
            "all_gitlabsast_high": gitlabsast_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_gitlabsast_low": gitlabsast_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_gitlabsast_medium": gitlabsast_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_twistlock_high": twistlock_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_twistlock_low": twistlock_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_twistlock_medium": twistlock_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_brakeman_high": brakeman_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_brakeman_low": brakeman_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_brakeman_medium": brakeman_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_gitlabcontainerscan_high": gitlabcontainerscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_gitlabcontainerscan_low": gitlabcontainerscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_gitlabcontainerscan_medium": gitlabcontainerscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(
                Sum("medium_vul")
            ),
            "all_gitlabsca_high": gitlabsca_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_gitlabsca_low": gitlabsca_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_gitlabsca_medium": gitlabsca_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_npmaudit_high": npmaudit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_npmaudit_low": npmaudit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_npmaudit_medium": npmaudit_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_nodejsscan_high": nodejsscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_nodejsscan_low": nodejsscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_nodejsscan_medium": nodejsscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_semgrepscan_high": semgrepscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_semgrepscan_low": semgrepscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_semgrepscan_medium": semgrepscan_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_tfsec_high": tfsec_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_tfsec_low": tfsec_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_tfsec_medium": tfsec_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_whitesource_high": whitesource_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_whitesource_low": whitesource_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_whitesource_medium": whitesource_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_checkmarx_high": checkmarx_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("high_vul")),
            "all_checkmarx_low": checkmarx_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("low_vul")),
            "all_checkmarx_medium": checkmarx_scan_db.objects.filter(
                username=username, project_id=project_id
            ).aggregate(Sum("medium_vul")),
            "all_closed_vuln": scans_query.all_vuln_count_data(
                username, project_id, query="Closed"
            ),
            "all_false_positive": scans_query.all_vuln_count_data(
                username, project_id, query="false"
            ),
            "message": all_notify,
        },
    )


def all_high_vuln(request):
    # add your scanner gloabl variable <scannername>
    zap_all_high = ""
    arachni_all_high = ""
    webinspect_all_high = ""
    netsparker_all_high = ""
    acunetix_all_high = ""
    burp_all_high = ""
    dependencycheck_all_high = ""
    findbugs_all_high = ""
    bandit_all_high = ""
    clair_all_high = ""
    trivy_all_high = ""
    gitlabsast_all_high = ""
    twistlock_all_high = ""
    gitlabcontainerscan_all_high = ""
    gitlabsca_all_high = ""
    npmaudit_all_high = ""
    nodejsscan_all_high = ""
    semgrepscan_all_high = ""
    tfsec_all_high = ""
    whitesource_all_high = ""
    checkmarx_all_high = ""
    openvas_all_high = ""
    nessus_all_high = ""
    brakeman_all_high = ""

    username = request.user.username
    all_notify = Notification.objects.unread()
    if request.GET["project_id"]:
        project_id = request.GET["project_id"]
        severity = request.GET["severity"]
    else:
        project_id = ""
        severity = ""
    # add your scanner name here <scannername>
    if severity == "All":
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, false_positive="No"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, false_positive="No"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    # add your scanner name here <scannername>
    elif severity == "All_Closed":
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, vuln_status="Closed", scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, vuln_status="Closed"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, vuln_status="Closed"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, vuln_status="Closed"
        )

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    # add your scanner name here <scannername>
    elif severity == "All_False_Positive":
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="Yes", scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, false_positive="Yes"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, false_positive="Yes"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, false_positive="Yes"
        )

        pentest_all_high = manual_scan_results_db.objects.filter(username=username)

    elif severity == "Network":
        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, false_positive="No"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, pentest_type="network"
        )

    elif severity == "Web":
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, false_positive="No", scanner='Burp'
        )
        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, pentest_type="web"
        )

    # add your scanner name here <scannername>
    elif severity == "Static":
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, false_positive="No"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, false_positive="No"
        )
        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, pentest_type="static"
        )

    elif severity == "High":

        # add your scanner name here <scannername>

        zap_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            severity="High",
            false_positive="No",
            scanner="zap",
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            severity="High",
            false_positive="No",
            scanner="Arachni",
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            severity__in=["Critical", "High"],
            false_positive="No",
            scanner="Webinspect",
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            severity="High",
            false_positive="No",
            scanner="Netsparker",
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            VulnSeverity="High",
            false_positive="No",
            scanner="Acunetix",
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            severity="High",
            false_positive="No",
            scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username,
            project_id=project_id,
            severity="High",
            false_positive="No",
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, risk="High", project_id=project_id, false_positive="No"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username,
            issue_severity="HIGH",
            project_id=project_id,
            false_positive="No",
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username,
            Severity="High",
            project_id=project_id,
            false_positive="No",
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username,
            Severity="High",
            project_id=project_id,
            false_positive="No",
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username,
            Severity="High",
            project_id=project_id,
            false_positive="No",
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username,
            Severity="High",
            project_id=project_id,
            false_positive="No",
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username,
                Severity="High",
                project_id=project_id,
                false_positive="No",
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username,
            Severity="High",
            project_id=project_id,
            false_positive="No",
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username,
            severity="High",
            project_id=project_id,
            false_positive="No",
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, threat="High", project_id=project_id, false_positive="No"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username,
            risk_factor="High",
            project_id=project_id,
            false_positive="No",
        )

        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, severity="High", project_id=project_id
        )

    elif severity == "Medium":

        # All Medium

        # add your scanner name here <scannername>

        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Medium", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Medium", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity__in=["Medium"], scanner="Webinspect"
        )
        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Medium", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, VulnSeverity="Medium", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Medium", scanner='Burp'
        )
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, project_id=project_id, severity="Medium"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, risk="Medium", project_id=project_id
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, issue_severity="MEDIUM", project_id=project_id
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, Severity="Medium", project_id=project_id
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, Severity="Medium", project_id=project_id
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, Severity="Medium", project_id=project_id
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, Severity="Medium", project_id=project_id
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, Severity="Medium", project_id=project_id
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, Severity="Medium", project_id=project_id
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, threat="Medium", project_id=project_id
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, risk_factor="Medium", project_id=project_id
        )

        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, severity="Medium", project_id=project_id
        )

    # All Low
    elif severity == "Low":
        # add your scanner name here <scannername>

        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Low", scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Low", scanner="Arachni"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity__in=["Low"], scanner="Webinspect"
        )
        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Low", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, VulnSeverity="Low", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, severity="Low", scanner='Burp'
        )
        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, project_id=project_id, severity="Low"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, risk="Low", project_id=project_id
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, issue_severity="LOW", project_id=project_id
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, Severity="Low", project_id=project_id
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, Severity="Low", project_id=project_id
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, Severity="Low", project_id=project_id
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, Severity="Low", project_id=project_id
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, Severity="Low", project_id=project_id
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, Severity="Low", project_id=project_id
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, threat="Low", project_id=project_id
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, risk_factor="Low", project_id=project_id
        )

        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, severity="Low", project_id=project_id
        )

    elif severity == "Total":
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, scanner="zap"
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            scanner="zap"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username,
            project_id=project_id,
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, project_id=project_id
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, project_id=project_id
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, project_id=project_id
        )

    elif severity == "False":
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            false_positive="Yes",
            scanner="zap",
        )
        arachni_all_high = arachni_scan_result_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        webinspect_all_high = webinspect_scan_result_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        netsparker_all_high = netsparker_scan_result_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        acunetix_all_high = acunetix_scan_result_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, false_positive="Yes", scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, false_positive="Yes", project_id=project_id
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, project_id=project_id, false_positive="Yes"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, project_id=project_id, false_positive="Yes"
        )

        pentest_all_high = ""

    elif severity == "Close":
        # add your scanner name here <scannername>
        zap_all_high = WebScanResultsDb.objects.filter(
            username=username,
            project_id=project_id,
            vuln_status="Closed",
            scanner="zap",
        )
        arachni_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed" , scanner="zap"
        )
        webinspect_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed", scanner="Webinspect"
        )

        netsparker_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed", scanner="Netsparker"
        )
        acunetix_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed", scanner="Acunetix"
        )
        burp_all_high = WebScanResultsDb.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed", scanner='Burp'
        )

        dependencycheck_all_high = dependencycheck_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )
        findbugs_all_high = findbugs_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )
        bandit_all_high = bandit_scan_results_db.objects.filter(
            username=username, vuln_status="Closed", project_id=project_id
        )
        clair_all_high = clair_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        trivy_all_high = trivy_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        gitlabsast_all_high = gitlabsast_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        twistlock_all_high = twistlock_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        brakeman_all_high = brakeman_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        gitlabcontainerscan_all_high = (
            gitlabcontainerscan_scan_results_db.objects.filter(
                username=username, project_id=project_id, vuln_status="Closed"
            )
        )

        gitlabsca_all_high = gitlabsca_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        npmaudit_all_high = npmaudit_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        nodejsscan_all_high = nodejsscan_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        semgrepscan_all_high = semgrepscan_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        tfsec_all_high = tfsec_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        whitesource_all_high = whitesource_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        checkmarx_all_high = checkmarx_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        openvas_all_high = ov_scan_result_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )
        nessus_all_high = nessus_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

        pentest_all_high = manual_scan_results_db.objects.filter(
            username=username, project_id=project_id, vuln_status="Closed"
        )

    else:
        return HttpResponseRedirect(
            reverse("dashboard:proj_data" + "?project_id=%s" % project_id)
        )

    # add your scanner name here <scannername>
    return render(
        request,
        "dashboard/all_high_vuln.html",
        {
            "zap_all_high": zap_all_high,
            "arachni_all_high": arachni_all_high,
            "webinspect_all_high": webinspect_all_high,
            "netsparker_all_high": netsparker_all_high,
            "acunetix_all_high": acunetix_all_high,
            "burp_all_high": burp_all_high,
            "dependencycheck_all_high": dependencycheck_all_high,
            "findbugs_all_high": findbugs_all_high,
            "bandit_all_high": bandit_all_high,
            "clair_all_high": clair_all_high,
            "trivy_all_high": trivy_all_high,
            "gitlabsast_all_high": gitlabsast_all_high,
            "twistlock_all_high": twistlock_all_high,
            "brakeman_all_high": brakeman_all_high,
            "gitlabcontainerscan_all_high": gitlabcontainerscan_all_high,
            "gitlabsca_all_high": gitlabsca_all_high,
            "npmaudit_all_high": npmaudit_all_high,
            "nodejsscan_all_high": nodejsscan_all_high,
            "semgrepscan_all_high": semgrepscan_all_high,
            "tfsec_all_high": tfsec_all_high,
            "whitesource_all_high": whitesource_all_high,
            "checkmarx_all_high": checkmarx_all_high,
            "openvas_all_high": openvas_all_high,
            "nessus_all_high": nessus_all_high,
            "project_id": project_id,
            "severity": severity,
            "pentest_all_high": pentest_all_high,
            "message": all_notify,
        },
    )


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    # if request.method == "POST":
    #     project_id = request.POST.get("project_id")
    #     report_type = request.POST.get("type")
    #     severity = request.POST.get("severity")
    #
    #     resource = AllResource()
    #
    #     all_data = scans_query.all_vuln_count(
    #         username=username, project_id=project_id, query=severity
    #     )
    #
    #     dataset = resource.export(all_data)
    #
    #     if report_type == "csv":
    #         response = HttpResponse(dataset.csv, content_type="text/csv")
    #         response["Content-Disposition"] = (
    #             'attachment; filename="%s.csv"' % project_id
    #         )
    #         return response
    #     if report_type == "json":
    #         response = HttpResponse(dataset.json, content_type="application/json")
    #         response["Content-Disposition"] = (
    #             'attachment; filename="%s.json"' % project_id
    #         )
    #         return response
