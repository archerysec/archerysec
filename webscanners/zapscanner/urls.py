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

from webscanners.zapscanner import views

app_name = "zapscanner"

urlpatterns = [
    path("zap_scan/", views.ZapScan.as_view(), name="zap_scan"),
    path("zap_settings/", views.ZapSetting.as_view(), name="zap_settings"),
    path(
        "zap_setting_update/",
        views.ZapSettingUpdate.as_view(),
        name="zap_setting_update",
    ),
]
