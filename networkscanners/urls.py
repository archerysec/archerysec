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
    path("launch_scan/", views.launch_scan, name="launch_scan"),
    path("ip_scan/", views.ip_scan, name="ip_scan"),

    path("nv_setting/", views.nv_setting, name="nv_setting"),
    path("nv_details/", views.nv_details, name="nv_details"),
    path("openvas_setting/", views.openvas_setting, name="openvas_setting"),
    path("openvas_details/", views.openvas_details, name="openvas_details"),
    path("xml_upload/", views.xml_upload, name="xml_upload"),
    path("net_scan_schedule/", views.net_scan_schedule, name="net_scan_schedule"),
    path(
        "del_net_scan_schedule/",
        views.del_net_scan_schedule,
        name="del_net_scan_schedule",
    ),
    # path("list_vuln/", views.list_vuln, name="list_vuln"),
    path("list_scans/", views.list_scans, name="list_scans"),
    path("list_vuln_info/", views.list_vuln_info, name="list_vuln_info"),
    path("scan_details/", views.scan_details, name="scan_details"),
    path("scan_delete/", views.scan_delete, name="scan_delete"),
    path("vuln_delete/", views.vuln_delete, name="vuln_delete"),
]
