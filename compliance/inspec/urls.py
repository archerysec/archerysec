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

from compliance.inspec import views

app_name = "inspec"

urlpatterns = [
    # Bandit scan list
    path("inspec_list/", views.inspec_list, name="inspec_list"),
    path("inspec_all_vuln/", views.list_vuln, name="inspec_all_vuln"),
    path("inspec_vuln_data/", views.inspec_vuln_data, name="inspec_vuln_data"),
    path("inspec_details/", views.inspec_details, name="inspec_details"),
    path("del_inspec/", views.del_inspec, name="del_inspec"),
    path("inspec_del_vuln/", views.inspec_del_vuln, name="inspec_del_vuln"),
    path("export/", views.export, name="export"),
]
