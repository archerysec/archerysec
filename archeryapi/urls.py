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
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from rest_framework.urlpatterns import format_suffix_patterns

from archeryapi import views

API_TITLE = "Archery API"
API_DESCRIPTION = (
    "Archery is an opensource vulnerability"
    " assessment and management tool which helps developers and "
    "pentesters to perform scans and manage vulnerabilities. Archery "
    "uses popular opensource tools to "
    "perform comprehensive scaning for web "
    "application and network. It also performs web application "
    "dynamic authenticated scanning and covers the whole applications "
    "by using selenium. The developers "
    "can also utilize the tool for implementation of their DevOps CI/CD environment. "
)

router = routers.DefaultRouter()

app_name = "archeryapi"

urlpatterns = [
    path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path(
        "docs/",
        include_docs_urls(
            title=API_TITLE,
            description=API_DESCRIPTION,
            public=True,
        ),
    ),
    path("webscan/", views.WebScan.as_view()),
    path("networkscan/", views.NetworkScan.as_view()),
    path("project/", views.Project.as_view()),
    path("webscanresult/", views.WebScanResult.as_view()),
    path("zapscanstatus/", views.ZapScanStatus.as_view()),
    path("uploadscan/", views.UploadScanResult.as_view()),
    path("zapstatusupdate/", views.UpdateZapStatus.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)
