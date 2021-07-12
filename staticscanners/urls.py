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
    path("report_import/", views.report_import, name="report_import"),

   # Static scans
    path("list_vuln/", views.list_vuln, name="list_vuln"),
    path("list_scans/", views.list_scans, name="list_scans"),
    path("list_vuln_info/", views.list_vuln_info, name="list_vuln_info"),
    path("scan_details/", views.scan_details, name="scan_details"),
    path("scan_delete/", views.scan_delete, name="scan_delete"),
    path("vuln_delete/", views.vuln_delete, name="vuln_delete"),
]
