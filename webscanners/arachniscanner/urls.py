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

from webscanners.arachniscanner import views

app_name = "arachniscanner"

urlpatterns = [
    # arachni
    path("arachni_settings/", views.arachni_settings, name="arachni_settings"),
    path(
        "arachni_setting_update/",
        views.arachni_setting_update,
        name="arachni_setting_update",
    ),
    path("arachni_scan_launch/", views.arachni_scan, name="arachni_scan_launch"),
    path("export/", views.export, name="export"),
]
