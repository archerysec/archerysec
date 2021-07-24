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

from compliance.dockle import views

app_name = "dockle"

urlpatterns = [
    # Bandit scan list
    path("dockle_list/", views.DockleScanList.as_view(), name="dockle_list"),
    path("dockle_all_vuln/", views.DockleVulnList.as_view(), name="dockle_all_vuln"),
    path("dockle_vuln_data/", views.DockleVulnData.as_view(), name="dockle_vuln_data"),
    path("dockle_details/", views.DockleDetails.as_view(), name="dockle_details"),
    path("del_dockle/", views.DockleDelete.as_view(), name="del_dockle"),
    path("dockle_del_vuln/", views.DockleVulnDelete.as_view(), name="dockle_del_vuln"),
    path("export/", views.export, name="export"),
]
