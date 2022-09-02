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

from cloudscanners import views

app_name = "cloudscanners"

urlpatterns = [
    # Static scans
    path("list_vuln/", views.CloudScanVulnList.as_view(), name="list_vuln"),
    path("list_scans/", views.CloudScanList.as_view(), name="list_scans"),
    path("list_vuln_info/", views.CloudScanVulnInfo.as_view(), name="list_vuln_info"),
    path("scan_details/", views.CloudScanDetails.as_view(), name="scan_details"),
    path("scan_delete/", views.CloudScanDelete.as_view(), name="scan_delete"),
    path("vuln_delete/", views.CloudScanVulnDelete.as_view(), name="vuln_delete"),
    path("vuln_mark/", views.CloudScanVulnMark.as_view(), name="vuln_mark"),
]
