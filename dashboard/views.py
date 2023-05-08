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
from rest_framework.permissions import AllowAny, IsAuthenticated

from compliance.models import DockleScanDb, InspecScanDb
from dashboard.scans_data import scans_query
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from pentest.models import PentestScanDb, PentestScanResultsDb
from projects.models import Month, MonthDb, MonthSqlite, ProjectDb
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from user_management import permissions
from webscanners.models import WebScanResultsDb, WebScansDb
from webscanners.resources import AllResource

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def trend_update():
    current_month = ""

    all_project = ProjectDb.objects.filter()

    for project in all_project:
        proj_id = project.uu_id
        project_id = project.id
        all_date_data = (
            ProjectDb.objects.annotate(month=Month("date_time"))
            .values("month")
            .annotate(total_critical=Sum("total_critical"))
            .annotate(total_high=Sum("total_high"))
            .annotate(total_medium=Sum("total_medium"))
            .annotate(total_low=Sum("total_low"))
            .order_by("month")
        )

        try:
            critical = all_date_data.first()["total_critical"]
            high = all_date_data.first()["total_high"]
            medium = all_date_data.first()["total_medium"]
            low = all_date_data.first()["total_low"]
        except:
            all_date_data = (
                ProjectDb.objects.annotate(month=MonthSqlite("date_time"))
                .values("month")
                .annotate(total_critical=Sum("total_critical"))
                .annotate(total_high=Sum("total_high"))
                .annotate(total_medium=Sum("total_medium"))
                .annotate(total_low=Sum("total_low"))
                .order_by("month")
            )
            critical = all_date_data.first()["total_critical"]
            high = all_date_data.first()["total_high"]
            medium = all_date_data.first()["total_medium"]
            low = all_date_data.first()["total_low"]

        all_month_data_display = MonthDb.objects.all()

        if len(all_month_data_display) == 0:
            add_data = MonthDb(
                project_id=project_id,
                month=current_month,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
            )
            add_data.save()

        for data in all_month_data_display:
            current_month = datetime.datetime.now().month
            if int(current_month) == 1:
                MonthDb.objects.filter(project_id=project_id, month="2").delete()
                MonthDb.objects.filter(project_id=project_id, month="3").delete()
                MonthDb.objects.filter(project_id=project_id, month="4").delete()
                MonthDb.objects.filter(project_id=project_id, month="5").delete()
                MonthDb.objects.filter(project_id=project_id, month="6").delete()
                MonthDb.objects.filter(project_id=project_id, month="7").delete()
                MonthDb.objects.filter(project_id=project_id, month="8").delete()
                MonthDb.objects.filter(project_id=project_id, month="9").delete()
                MonthDb.objects.filter(project_id=project_id, month="10").delete()
                MonthDb.objects.filter(project_id=project_id, month="11").delete()
                MonthDb.objects.filter(project_id=project_id, month="12").delete()

            match_data = MonthDb.objects.filter(
                project_id=project_id, month=current_month
            )
            if len(match_data) == 0:
                add_data = MonthDb(
                    project_id=project_id,
                    month=current_month,
                    critical=critical,
                    high=high,
                    medium=medium,
                    low=low,
                )
                add_data.save()

            elif int(data.month) == int(current_month):
                MonthDb.objects.filter(month=current_month).update(
                    critical=critical, high=high, medium=medium, low=low
                )

        total_vuln = scans_query.all_vuln(project_id=proj_id, query="total")
        total_critical = scans_query.all_vuln(project_id=proj_id, query="critical")
        total_high = scans_query.all_vuln(project_id=proj_id, query="high")
        total_medium = scans_query.all_vuln(project_id=proj_id, query="medium")
        total_low = scans_query.all_vuln(project_id=proj_id, query="low")

        total_open = scans_query.all_vuln_count_data(project_id=proj_id, query="Open")
        total_close = scans_query.all_vuln_count_data(
            project_id=proj_id, query="Closed"
        )
        total_false = scans_query.all_vuln_count_data(project_id=proj_id, query="false")

        total_net = scans_query.all_net(project_id=proj_id, query="total")
        total_web = scans_query.all_web(project_id=proj_id, query="total")
        total_static = scans_query.all_static(project_id=proj_id, query="total")
        total_cloud = scans_query.all_cloud(project_id=proj_id, query="total")

        critical_net = scans_query.all_net(proj_id, query="critical")
        critical_web = scans_query.all_web(proj_id, query="critical")
        critical_static = scans_query.all_static(proj_id, query="critical")
        critical_cloud = scans_query.all_cloud(proj_id, query="critical")

        high_net = scans_query.all_net(proj_id, query="high")
        high_web = scans_query.all_web(proj_id, query="high")
        high_static = scans_query.all_static(proj_id, query="high")
        high_cloud = scans_query.all_cloud(proj_id, query="high")

        medium_net = scans_query.all_net(proj_id, query="medium")
        medium_web = scans_query.all_web(proj_id, query="medium")
        medium_static = scans_query.all_static(proj_id, query="medium")
        medium_cloud = scans_query.all_cloud(proj_id, query="medium")

        low_net = scans_query.all_net(proj_id, query="low")
        low_web = scans_query.all_web(proj_id, query="low")
        low_static = scans_query.all_static(proj_id, query="low")
        low_cloud = scans_query.all_cloud(proj_id, query="low")

        ProjectDb.objects.filter(uu_id=proj_id).update(
            total_vuln=total_vuln,
            total_open=total_open,
            total_close=total_close,
            total_false=total_false,
            total_net=total_net,
            total_web=total_web,
            total_static=total_static,
            total_cloud=total_cloud,
            total_critical=total_critical,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            critical_net=critical_net,
            critical_web=critical_web,
            critical_static=critical_static,
            critical_cloud=critical_cloud,
            high_net=high_net,
            high_web=high_web,
            high_static=high_static,
            high_cloud=high_cloud,
            medium_net=medium_net,
            medium_web=medium_web,
            medium_static=medium_static,
            medium_cloud=medium_cloud,
            low_net=low_net,
            low_web=low_web,
            low_static=low_static,
            low_cloud=low_cloud,
        )


def dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """
    scanners = "vscanners"

    trend_update()

    all_project = ProjectDb.objects.filter(organization=request.user.organization)

    current_year = datetime.datetime.now().year

    all_notify = Notification.objects.unread()

    all_month_data_display = (
        MonthDb.objects.all().values("month", "critical", "high", "medium", "low").distinct()
    )
    # print(MonthDb.objects.filter().values('month', 'high', 'medium', 'low').distinct())

    return render(
        request,
        "dashboard/index.html",
        {
            "all_project": all_project,
            "scanners": scanners,
            "total_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_vuln")
            ),
            "open_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_open")
            ),
            "close_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_close")
            ),
            "false_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_false")
            ),
            "net_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(Sum("total_net")),
            "web_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(Sum("total_web")),
            "static_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_static")
            ),
            "cloud_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_cloud")
            ),
            "critical_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_critical")
            ),
            "high_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_high")
            ),
            "medium_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("total_medium")
            ),
            "low_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(Sum("total_low")),
            "critical_net_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("critical_net")
            ),
            "critical_web_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("critical_web")
            ),
            "critical_static_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("critical_static")
            ),
            "critical_cloud_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("critical_cloud")
            ),
            "high_net_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("high_net")
            ),
            "high_web_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("high_web")
            ),
            "high_static_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("high_static")
            ),
            "high_cloud_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("high_cloud")
            ),
            "medium_net_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("medium_net")
            ),
            "medium_web_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("medium_web")
            ),
            "medium_static_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("medium_static")
            ),
            "medium_cloud_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("medium_cloud")
            ),
            "low_net_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("low_net")
            ),
            "low_web_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("low_web")
            ),
            "low_static_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("low_static")
            ),
            "low_cloud_count_project": ProjectDb.objects.filter(organization=request.user.organization).aggregate(
                Sum("low_cloud")
            ),
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

    all_project = ProjectDb.objects.filter(organization=request.user.organization)

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
    all_project = ProjectDb.objects.filter(organization=request.user.organization)
    if request.GET["uu_id"]:
        uu_id = request.GET["uu_id"]
    else:
        uu_id = ""

    project_dat = ProjectDb.objects.filter(uu_id=uu_id, organization=request.user.organization)
    web_scan_dat = WebScansDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    static_scan = StaticScansDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    cloud_scan = CloudScansDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    network_dat = NetworkScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    inspec_dat = InspecScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    dockle_dat = DockleScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)
    compliance_dat = chain(inspec_dat, dockle_dat)
    all_comp_inspec = InspecScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)

    all_comp_dockle = InspecScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = PentestScanDb.objects.filter(project__uu_id=uu_id, organization=request.user.organization)

    all_notify = Notification.objects.unread()

    all_critical = scans_query.all_vuln(project_id=uu_id, query="critical")
    all_high = scans_query.all_vuln(project_id=uu_id, query="high")
    all_medium = scans_query.all_vuln(project_id=uu_id, query="medium")
    all_low = scans_query.all_vuln(project_id=uu_id, query="low")

    total = all_critical, all_high, all_medium, all_low

    tota_vuln = sum(total)

    return render(
        request,
        "dashboard/project.html",
        {
            "project_id": uu_id,
            "tota_vuln": tota_vuln,
            "all_vuln": scans_query.all_vuln(project_id=uu_id, query="total"),
            "total_web": scans_query.all_web(project_id=uu_id, query="total"),
            "total_static": scans_query.all_static(project_id=uu_id, query="total"),
            "total_cloud": scans_query.all_cloud(project_id=uu_id, query="total"),
            "total_network": scans_query.all_net(project_id=uu_id, query="total"),
            "all_critical": all_critical,
            "all_high": all_high,
            "all_medium": all_medium,
            "all_low": all_low,
            "all_web_critical": scans_query.all_web(project_id=uu_id, query="critical"),
            "all_web_high": scans_query.all_web(project_id=uu_id, query="high"),
            "all_web_medium": scans_query.all_web(project_id=uu_id, query="medium"),
            "all_network_medium": scans_query.all_net(project_id=uu_id, query="medium"),
            "all_network_critical": scans_query.all_net(project_id=uu_id, query="critical"),
            "all_network_high": scans_query.all_net(project_id=uu_id, query="high"),
            "all_web_low": scans_query.all_web(project_id=uu_id, query="low"),
            "all_network_low": scans_query.all_net(project_id=uu_id, query="low"),
            "all_project": all_project,
            "project_dat": project_dat,
            "web_scan_dat": web_scan_dat,
            "all_static_critical": scans_query.all_static(project_id=uu_id, query="critical"),
            "all_static_high": scans_query.all_static(project_id=uu_id, query="high"),
            "all_static_medium": scans_query.all_static(
                project_id=uu_id, query="medium"
            ),
            "all_static_low": scans_query.all_static(project_id=uu_id, query="low"),
            "static_scan": static_scan,
            "all_cloud_critical": scans_query.all_cloud(project_id=uu_id, query="critical"),
            "all_cloud_high": scans_query.all_cloud(project_id=uu_id, query="high"),
            "all_cloud_medium": scans_query.all_cloud(
                project_id=uu_id, query="medium"
            ),
            "all_cloud_low": scans_query.all_cloud(project_id=uu_id, query="low"),
            "cloud_scan": cloud_scan,
            "pentest": pentest,
            "network_dat": network_dat,
            "all_compliance_failed": scans_query.all_compliance(
                project_id=uu_id, query="failed"
            ),
            "all_compliance_passed": scans_query.all_compliance(
                project_id=uu_id, query="passed"
            ),
            "all_compliance_skipped": scans_query.all_compliance(
                project_id=uu_id, query="skipped"
            ),
            "total_compliance": scans_query.all_compliance(
                project_id=uu_id, query="total"
            ),
            "all_compliance": all_compliance_seg,
            "compliance_dat": compliance_dat,
            "inspec_dat": inspec_dat,
            "dockle_dat": dockle_dat,
            "all_closed_vuln": scans_query.all_vuln_count_data(uu_id, query="Closed"),
            "all_false_positive": scans_query.all_vuln_count_data(uu_id, query="false"),
            "message": all_notify,
        },
    )


def all_high_vuln(request):
    # add your scanner gloabl variable <scannername>
    web_all_high = ""
    sast_all_high = ""
    cloud_all_high = ""
    net_all_high = ""
    pentest_all_high = ""

    all_notify = Notification.objects.unread()
    if request.GET["project_id"]:
        project_uu_id = request.GET["project_id"]
        severity = request.GET["severity"]
        if project_uu_id == "none":
            project_id = ""
        else:
            project_id = (
                ProjectDb.objects.filter(uu_id=project_uu_id, organization=request.user.organization).values("id").get()["id"]
            )
    else:
        project_id = ""
        severity = ""
    if severity == "All":
        web_all_high = WebScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        sast_all_high = StaticScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        cloud_all_high = CloudScansResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        net_all_high = NetworkScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(organization=request.user.organization)

    elif severity == "All_Closed":
        web_all_high = WebScanResultsDb.objects.filter(vuln_status="Closed", organization=request.user.organization)
        sast_all_high = StaticScanResultsDb.objects.filter(vuln_status="Closed", organization=request.user.organization)
        cloud_all_high = CloudScansResultsDb.objects.filter(vuln_status="Closed", organization=request.user.organization)
        net_all_high = NetworkScanResultsDb.objects.filter(vuln_status="Closed", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(organization=request.user.organization)

    # add your scanner name here <scannername>
    elif severity == "All_False_Positive":
        web_all_high = WebScanResultsDb.objects.filter(false_positive="Yes", organization=request.user.organization)
        sast_all_high = StaticScanResultsDb.objects.filter(false_positive="Yes", organization=request.user.organization)
        cloud_all_high = CloudScansResultsDb.objects.filter(false_positive="Yes", organization=request.user.organization)
        net_all_high = NetworkScanResultsDb.objects.filter(false_positive="Yes", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(organization=request.user.organization)

    elif severity == "Network":
        net_all_high = NetworkScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)

    elif severity == "Web":
        web_all_high = WebScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(pentest_type="web", organization=request.user.organization)

    # add your scanner name here <scannername>
    elif severity == "Static":
        sast_all_high = StaticScanResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(pentest_type="static", organization=request.user.organization)

    elif severity == "Cloud":
        cloud_all_high = CloudScansResultsDb.objects.filter(false_positive="No", organization=request.user.organization)
        pentest_all_high = PentestScanResultsDb.objects.filter(pentest_type="cloud", organization=request.user.organization)

    elif severity == "Critical":

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, severity="Critical", false_positive="No",
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, severity="Critical", false_positive="No",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, severity="Critical", false_positive="No",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, severity="Critical", false_positive="No",
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Critical", project_id=project_id,
            organization=request.user.organization
        )

    elif severity == "High":

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, severity="High", false_positive="No", organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, severity="High", false_positive="No",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, severity="High", false_positive="No",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, severity="High", false_positive="No",
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="High", project_id=project_id,
            organization=request.user.organization
        )

    elif severity == "Medium":

        # All Medium

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, severity="Medium",
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, severity="Medium",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, severity="Medium",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, severity="Medium",
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Medium", project_id=project_id,
            organization=request.user.organization
        )

    # All Low
    elif severity == "Low":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, severity="Low",
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, severity="Low",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, severity="Low",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, severity="Low",
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Low", project_id=project_id,
            organization=request.user.organization
        )

    elif severity == "Total":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(project_id=project_id, organization=request.user.organization)

    elif severity == "False":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, false_positive="Yes",
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, false_positive="Yes",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, false_positive="Yes",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, false_positive="Yes",
            organization=request.user.organization
        )

        pentest_all_high = ""

    elif severity == "Close":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, vuln_status="Closed",
            organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, vuln_status="Closed",
            organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, vuln_status="Closed",
            organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, vuln_status="Closed",
            organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            project_id=project_id, vuln_status="Closed",
            organization=request.user.organization
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
            "web_all_high": web_all_high,
            "sast_all_high": sast_all_high,
            "cloud_all_high": cloud_all_high,
            "net_all_high": net_all_high,
            "pentest_all_high": pentest_all_high,
            "project_id": project_id,
            "severity": severity,
            "message": all_notify,
        },
    )


def export(request):
    """
    :param request:
    :return:
    """

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        report_type = request.POST.get("type")
        severity = request.POST.get("severity")

        resource = AllResource()

        all_data = scans_query.all_vuln_count(project_id=project_id, query=severity)

        dataset = resource.export(all_data)

        if report_type == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = (
                'attachment; filename="%s.csv"' % project_id
            )
            return response
        if report_type == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = (
                'attachment; filename="%s.json"' % project_id
            )
            return response
