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
from django.conf import settings
from django.urls import include, path
from django.conf.urls.static import static
from django.contrib import admin
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token, refresh_jwt_token

from rest_framework.authtoken import views

import notifications.urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('webscanners/', include('webscanners.urls')),
    path('zapscanner/', include('webscanners.zapscanner.urls')),
    path('acunetixscanner/', include('webscanners.acunetixscanner.urls')),
    path('burpscanner/', include('webscanners.burpscanner.urls')),
    path('arachniscanner/', include('webscanners.arachniscanner.urls')),
    path('netsparkerscanner/', include('webscanners.netsparkerscanner.urls')),
    path('webinspectscanner/', include('webscanners.webinspectscanner.urls')),
    path('projects/', include('projects.urls')),
    path('networkscanners/', include('networkscanners.urls')),
    path('staticscanners/', include('staticscanners.urls')),
    path('banditscanner/', include('staticscanners.banditscanner.urls')),
    path('dependencycheck/', include('staticscanners.dependencycheck.urls')),
    path('findbugs/', include('staticscanners.findbugs.urls')),
    path('clair/', include('staticscanners.clair.urls')),
    path('trivy/', include('staticscanners.trivy.urls')),
    path('gitlabsast/', include('staticscanners.gitlabsast.urls')),
    path('gitlabcontainerscan/', include('staticscanners.gitlabcontainerscan.urls')),
    path('gitlabsca/', include('staticscanners.gitlabsca.urls')),
    path('npmaudit/', include('staticscanners.npmaudit.urls')),
    path('nodejsscan/', include('staticscanners.nodejsscan.urls')),
    path('semgrepscan/', include('staticscanners.semgrep.urls')),
    path('tfsec/', include('staticscanners.tfsec.urls')),
    path('whitesource/', include('staticscanners.whitesource.urls')),
    path('checkmarx/', include('staticscanners.checkmarx.urls')),
    path('inspec/', include('compliance.inspec.urls')),
    path('dockle/', include('compliance.dockle.urls')),
    path('retirejsscanner/', include('staticscanners.retirejsscan.urls')),
    path('api/', include('archeryapi.urls')),
    path('twistlock/', include('staticscanners.twistlock.urls')),
    path('brakeman/', include('staticscanners.brakeman.urls')),
    path('debcvescan/', include('staticscanners.debcvescan.urls')),

    # path('scanapi/', include('APIScan.urls')),
    path('inbox/notifications/', include(notifications.urls, namespace='notifications')),
    path('nessus/', include('networkscanners.nessus.urls')),

    # Default url
    path(r'', include('dashboard.urls')),

    # API authentication
    path('api-token-auth/', obtain_jwt_token),
    path('api-token-verify/', verify_jwt_token),
    path('api-token-refresh/', refresh_jwt_token),

    # JIRA
    path('jira/', include('jiraticketing.urls')),

    # Tools App
    path('tools/', include('tools.urls')),

    # Manual App
    path('manual_scan/', include('manual_scan.urls')),
]

urlpatterns = urlpatterns + \
              static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG:
    import debug_toolbar

    urlpatterns = [
                      path('__debug__/', include(debug_toolbar.urls)),
                  ] + urlpatterns
