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
from archeryapi import views
from rest_framework.documentation import include_docs_urls
from rest_framework.urlpatterns import format_suffix_patterns

API_TITLE = 'Archery API'
API_DESCRIPTION = 'Archery is an opensource vulnerability' \
                  ' assessment and management tool which helps developers and ' \
                  'pentesters to perform scans and manage vulnerabilities. Archery ' \
                  'uses popular opensource tools to ' \
                  'perform comprehensive scaning for web ' \
                  'application and network. It also performs web application ' \
                  'dynamic authenticated scanning and covers the whole applications ' \
                  'by using selenium. The developers ' \
                  'can also utilize the tool for implementation of their DevOps CI/CD environment. '

router = routers.DefaultRouter()

app_name = 'archeryapi'

urlpatterns = [
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('docs/', include_docs_urls(title=API_TITLE, description=API_DESCRIPTION, public=True, )),
    path('webscan/', views.WebScan.as_view()),
    path('networkscan/', views.NetworkScan.as_view()),
    path('networkscanresult/', views.NetworkScanResult.as_view()),
    path('project/', views.Project.as_view()),
    path('webscanresult/', views.WebScanResult.as_view()),
    path('zapscanstatus/', views.ZapScanStatus.as_view()),
    path('burpscanstatus/', views.BurpScanStatus.as_view()),
    path('arachniscanstatus/', views.ArachniScanStatus.as_view()),
    path('dependencycheckscanstatus/', views.DependencycheckScanStatus.as_view()),
    path('findbugscanstatus/', views.FindbugsScanStatus.as_view()),
    path('retirejsscanstatus/', views.RetirejsScanStatus.as_view()),
    path('clairscanstatus/', views.ClairScanStatus.as_view()),
    path('nodejsscanstatus/', views.NodejsScanStatus.as_view()),
    path('npmauditscanstatus/', views.NpmauditScanStatus.as_view()),
    path('trivyscanstatus/', views.TrivyScanStatus.as_view()),
    path('banditscanstatus/', views.BanditScanStatus.as_view()),
    path('netsparkerscanstatus/', views.NetsparkerScanStatus.as_view()),
    path('webinspectscanstatus/', views.WebinspectScanStatus.as_view()),
    path('acunetixscanresult/', views.AcunetixScanStatus.as_view()),
    path('uploadscan/', views.UploadScanResult.as_view()),
    path('zapstatusupdate/', views.UpdateZapStatus.as_view()),
    path('createuser/', views.CreateUsers.as_view())

]

urlpatterns = format_suffix_patterns(urlpatterns)
