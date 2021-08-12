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

from django.urls import include, path

from networkscanners import views

app_name = "networkscanners"

urlpatterns = [
    path("launch_scan/", views.OpenvasLaunchScan.as_view(), name="launch_scan"),
    path("ip_scan/", views.NetworkScan.as_view(), name="ip_scan"),
    path("nv_setting/", views.OpenvasSettingEnable.as_view(), name="nv_setting"),
    path("nv_details/", views.OpenvasSettingEnableDetails.as_view(), name="nv_details"),
    path("openvas_setting/", views.OpenvasSetting.as_view(), name="openvas_setting"),
    path("openvas_details/", views.OpenvasDetails.as_view(), name="openvas_details"),
    path(
        "net_scan_schedule/",
        views.NetworkScanSchedule.as_view(),
        name="net_scan_schedule",
    ),
    path(
        "del_net_scan_schedule/",
        views.NetworkScanScheduleDelete.as_view(),
        name="del_net_scan_schedule",
    ),
    path("list_scans/", views.NetworkScanList.as_view(), name="list_scans"),
    path("list_vuln_info/", views.NetworkScanVulnInfo.as_view(), name="list_vuln_info"),
    path("scan_details/", views.NetworkScanDetails.as_view(), name="scan_details"),
    path("scan_delete/", views.NetworkScanDelete.as_view(), name="scan_delete"),
    path("vuln_delete/", views.NetworkScanVulnDelete.as_view(), name="vuln_delete"),
    path("vuln_mark/", views.NetworkScanVulnMark.as_view(), name="vuln_mark"),
]
