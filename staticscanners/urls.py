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

from staticscanners import views

app_name = "staticscanners"

urlpatterns = [
    path("report_import/", views.UploadJSONReport.as_view(), name="report_import"),
    # Static scans
    path("list_vuln/", views.SastScanVulnList.as_view(), name="list_vuln"),
    path("list_scans/", views.SastScanList.as_view(), name="list_scans"),
    path("list_vuln_info/", views.SastScanVulnInfo.as_view(), name="list_vuln_info"),
    path("scan_details/", views.SastScanDetails.as_view(), name="scan_details"),
    path("scan_delete/", views.SastScanDelete.as_view(), name="scan_delete"),
    path("vuln_delete/", views.SastScanVulnDelete.as_view(), name="vuln_delete"),
    path("vuln_mark/", views.SastScanVulnMark.as_view(), name="vuln_mark"),
]
