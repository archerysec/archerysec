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

"""archerysecurity URL Configuration

"""
import notifications.urls
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("webscanners/", include("webscanners.urls")),
    path("zapscanner/", include("webscanners.zapscanner.urls")),
    path("burpscanner/", include("webscanners.burpscanner.urls")),
    path("arachniscanner/", include("webscanners.arachniscanner.urls")),
    path("projects/", include("projects.urls")),
    path("networkscanners/", include("networkscanners.urls")),
    path("staticscanners/", include("staticscanners.urls")),
    path("cloudscanners/", include("cloudscanners.urls")),
    path("inspec/", include("compliance.inspec.urls")),
    path("dockle/", include("compliance.dockle.urls")),
    path("api/", include("archeryapi.urls")),
    # path('scanapi/', include('APIScan.urls')),
    path(
        "inbox/notifications/", include(notifications.urls, namespace="notifications")
    ),
    # path("nessus/", include("networkscanners.nessus.urls")),
    # Default url
    path(r"", include("dashboard.urls")),
    # JIRA
    path("jira/", include("jiraticketing.urls")),
    # Tools App
    path("tools/", include("tools.urls")),
    # Manual App
    path("pentest/", include("pentest.urls")),
    # settings app
    path("settings/", include("archerysettings.urls")),
    path("archerysec/api/v1/auth/", include("authentication.urls")),
    path("auth/", include("authentication.urls")),
    path("users/", include("user_management.urls")),
    path("report-upload/", include("report_upload.urls")),
    # cicd app
    path("cicd/", include("cicd.urls")),
]

urlpatterns = urlpatterns + static(
    settings.STATIC_URL, document_root=settings.STATIC_ROOT
)

if settings.DEBUG:
    import debug_toolbar

    urlpatterns = [
        path("__debug__/", include(debug_toolbar.urls)),
    ] + urlpatterns
