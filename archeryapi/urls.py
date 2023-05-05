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
from webscanners.views import WebScanList, WebScanVulnInfo
from networkscanners.views import NetworkScanList, NetworkScanVulnInfo
from staticscanners.views import SastScanList, SastScanVulnInfo
from projects.views import ProjectList
from authentication.views import MyTokenObtainPairView, Logout, UserSettings, ForgotPassword, ResetPassword, UpdatePassword
from rest_framework_simplejwt import views as jwt_views
from webscanners.zapscanner.views import ZapScan, ZapSetting, ZapSettingUpdate
from webscanners.burpscanner.views import BurpSetting, BurpScanLaunch
from webscanners.arachniscanner.views import ArachniScan, ArachniSetting, ArachniSettingUpdate
from networkscanners.views import OpenvasLaunchScan, OpenvasDetails, OpenvasSetting
from jiraticketing.views import LinkJiraTicket
from user_management.views import UserRoles, Roles, UsersList, UsersEdit, Profile, Users

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
    # path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path(
        "v1/docs/",
        include_docs_urls(
            title=API_TITLE,
            description=API_DESCRIPTION,
            public=True,
        ),
    ),

    # Authentication API
    path("v1/", views.ApiTest.as_view(), name="api_test"),
    path("v1/auth/login/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("v1/auth/refresh-token/", jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path("v1/auth/logout/", Logout.as_view()),
    path("v1/auth/user-settings/", UserSettings.as_view()),
    path("v1/auth/forgot-pass/", ForgotPassword.as_view()),
    path("v1/auth/reset-pass/", ResetPassword.as_view()),
    path("v1/auth/update-pass/", UpdatePassword.as_view()),

    # User management API
    path("v1/users/user/", Users.as_view()),
    path("v1/users/user/<str:uu_id>/", Users.as_view()),
    path("v1/users/profile/", Profile.as_view()),
    path("v1/users/roles/", Roles.as_view()),
    path("v1/users/roles/<str:uu_id>/", Roles.as_view()),

    path("v1/uploadscan/", views.UploadScanResult.as_view()),
    path("access-key/", views.APIKey.as_view(), name="access-key"),
    path("access-key-delete/", views.DeleteAPIKey.as_view(), name="access-key-delete"),

    # Project API
    path("v1/project-list/", ProjectList.as_view()),
    path("v1/project-create/", views.CreateProject.as_view()),

    # Web scans API endpoints
    path("v1/web-scans/", WebScanList.as_view()),
    path("v1/web-scans/<str:uu_id>/", WebScanVulnInfo.as_view()),

    # Network scan API endpoints
    path("v1/network-scans/", NetworkScanList.as_view()),
    path("v1/network-scans/<str:uu_id>/", NetworkScanVulnInfo.as_view()),

    # Static scan API endpoints
    path("v1/sast-scans/", SastScanList.as_view()),
    path("v1/sast-scans/<str:uu_id>/", SastScanVulnInfo.as_view()),

    # CI/CD policy API endpoints
    path("v1/get-cicd-policies/<str:uu_id>/", views.GetCicdPolicies.as_view()),

    # ZAP Scan
    path("v1/zap-scan/", ZapScan.as_view()),
    path("v1/zap-settings/", ZapSetting.as_view()),
    path("v1/zap-settings-update/", ZapSettingUpdate.as_view()),

    # Burp Scan
    path("v1/burp-settings/", BurpSetting.as_view()),
    path("v1/burp-scans/", BurpScanLaunch.as_view()),

    # Arachni Scan
    path("v1/arachni-scans/", ArachniScan.as_view()),
    path("v1/arachni-settings/", ArachniSetting.as_view()),
    path("v1/arachni-setting-update/", ArachniSettingUpdate.as_view()),

    # Openvas Scan
    path("v1/openvas-scans/", OpenvasLaunchScan.as_view()),
    path("v1/openvas-settings/", OpenvasSetting.as_view()),
    path("v1/openvas-setting-update/", OpenvasDetails.as_view()),

    # All Scans
    path("v1/all-scans/", views.ListAllScanResults.as_view()),

    # Update JIRA
    path("v1/update-jira/", views.UpdateJiraTicket.as_view()),

]

urlpatterns = format_suffix_patterns(urlpatterns)
