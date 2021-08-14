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

from archerysettings import views

app_name = "archerysettings"

urlpatterns = [
    path("settings/", views.Settings.as_view(), name="settings"),
    path("del_setting/", views.DeleteSettings.as_view(), name="del_setting"),
    path("email_setting/", views.EmailSetting.as_view(), name="email_setting"),
]
