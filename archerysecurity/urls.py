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
from rest_framework_jwt.views import (obtain_jwt_token, refresh_jwt_token,
                                      verify_jwt_token)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("webscanners/", include("webscanners.urls")),
    path("zapscanner/", include("webscanners.zapscanner.urls")),
    path("burpscanner/", include("webscanners.burpscanner.urls")),
    path("arachniscanner/", include("webscanners.arachniscanner.urls")),
    path("webinspectscanner/", include("webscanners.webinspectscanner.urls")),
    path("projects/", include("projects.urls")),
    path("networkscanners/", include("networkscanners.urls")),
    path("staticscanners/", include("staticscanners.urls")),
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
    # API authentication
    path("api-token-auth/", obtain_jwt_token),
    path("api-token-verify/", verify_jwt_token),
    path("api-token-refresh/", refresh_jwt_token),
    # JIRA
    path("jira/", include("jiraticketing.urls")),
    # Tools App
    path("tools/", include("tools.urls")),
    # Manual App
    path("manual_scan/", include("manual_scan.urls")),
]

urlpatterns = urlpatterns + static(
    settings.STATIC_URL, document_root=settings.STATIC_ROOT
)

if settings.DEBUG:
    import debug_toolbar

    urlpatterns = [
        path("__debug__/", include(debug_toolbar.urls)),
    ] + urlpatterns
