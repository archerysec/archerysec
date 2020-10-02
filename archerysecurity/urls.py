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

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls import url, include
from django.conf.urls.static import static
from django.contrib import admin
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token
from rest_framework_jwt.views import refresh_jwt_token
import notifications.urls

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^webscanners/', include('webscanners.urls')),
    url(r'^zapscanner/', include('webscanners.zapscanner.urls')),
    url(r'^acunetixscanner/', include('webscanners.acunetixscanner.urls')),
    url(r'^burpscanner/', include('webscanners.burpscanner.urls')),
    url(r'^arachniscanner/', include('webscanners.arachniscanner.urls')),
    url(r'^netsparkerscanner/', include('webscanners.netsparkerscanner.urls')),
    url(r'^webinspectscanner/', include('webscanners.webinspectscanner.urls')),
    url(r'^projects/', include('projects.urls')),
    url(r'^networkscanners/', include('networkscanners.urls')),
    url(r'^staticscanners/', include('staticscanners.urls')),
    url(r'^banditscanner/', include('staticscanners.banditscanner.urls')),
    url(r'^dependencycheck/', include('staticscanners.dependencycheck.urls')),
    url(r'^findbugs/', include('staticscanners.findbugs.urls')),
    url(r'^clair/', include('staticscanners.clair.urls')),
    url(r'^trivy/', include('staticscanners.trivy.urls')),
    url(r'^gitlabsast/', include('staticscanners.gitlabsast.urls')),
    url(r'^gitlabcontainerscan/', include('staticscanners.gitlabcontainerscan.urls')),
    url(r'^gitlabsca/', include('staticscanners.gitlabsca.urls')),
    url(r'^npmaudit/', include('staticscanners.npmaudit.urls')),
    url(r'^nodejsscan/', include('staticscanners.nodejsscan.urls')),
    url(r'^semgrepscan/', include('staticscanners.semgrep.urls')),
    url(r'^tfsec/', include('staticscanners.tfsec.urls')),
    url(r'^whitesource/', include('staticscanners.whitesource.urls')),
    url(r'^checkmarx/', include('staticscanners.checkmarx.urls')),
    url(r'^inspec/', include('compliance.inspec.urls')),
    url(r'^dockle/', include('compliance.dockle.urls')),
    url(r'^retirejsscanner/', include('staticscanners.retirejsscan.urls')),
    url(r'^api/', include('archeryapi.urls')),
    # url(r'^scanapi/', include('APIScan.urls')),
    url(r'^vfeed/', include('vFeedgui.urls')),
    url('^inbox/notifications/', include(notifications.urls, namespace='notifications')),

    # Default url
    url(r'', include('dashboard.urls')),

    # API authentication
    url(r'^api-token-auth/', obtain_jwt_token),
    url(r'^api-token-verify/', verify_jwt_token),
    url(r'^api-token-refresh/', refresh_jwt_token),

    # JIRA
    url(r'^jira/', include('jiraticketing.urls')),

    # Tools App
    url(r'^tools/', include('tools.urls')),

    # Manual App
    url(r'^manual_scan/', include('manual_scan.urls')),
]

urlpatterns = urlpatterns + \
              static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG:
    import debug_toolbar

    urlpatterns = [
                      url(r'^__debug__/', include(debug_toolbar.urls)),
                  ] + urlpatterns