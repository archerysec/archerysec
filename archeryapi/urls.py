#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from django.conf.urls import url, include
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

urlpatterns = [
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^docs/', include_docs_urls(title=API_TITLE, description=API_DESCRIPTION, public=True, )),
    url(r'webscan/', views.WebScan.as_view()),
    url(r'networkscan/', views.NetworkScan.as_view()),
    url(r'project/', views.Project.as_view()),
    url(r'webscanresult/', views.WebScanResult.as_view()),
    url(r'zapscanstatus/', views.ZapScanStatus.as_view()),
    url(r'networkscanresult/', views.NetworkScanResult.as_view()),
    url(r'uploadscan/', views.UpladScanResult.as_view()),
    url(r'createuser/', views.CreateUsers.as_view())

]

urlpatterns = format_suffix_patterns(urlpatterns)
