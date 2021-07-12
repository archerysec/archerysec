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

from webscanners import web_views
from webscanners import views

app_name = "webscanners"

urlpatterns = [
    path("login/", web_views.login, name="login"),
    path("signup/", web_views.signup, name="signup"),
    path("auth/", web_views.auth_view, name="auth"),
    path("logout/", web_views.logout, name="logout"),
    path("loggedin/", web_views.loggedin, name="loggedin"),
    path("", web_views.index, name="index"),
    path("setting/", web_views.setting, name="setting"),
    # Burp scans
    path("xml_upload/", web_views.xml_upload, name="xml_upload"),
    path(
        "email_setting/",
        web_views.email_setting,
        name="email_setting",
    ),
    path(
        "cookie_add/",
        web_views.add_cookies,
        name="cookie_add",
    ),
    path("web_task_launch/", web_views.web_task_launch, name="web_task_launch"),
    path("web_scan_schedule/", web_views.web_scan_schedule, name="web_scan_schedule"),
    path(
        "del_web_scan_schedule/",
        web_views.del_web_scan_schedule,
        name="del_web_scan_schedule",
    ),
    path("sel_login/", web_views.sel_login, name="sel"),
    path("save_cookie/", web_views.save_cookie, name="save_cookie"),
    path("exclude_url/", web_views.exclude_url, name="exclude_url"),
    path("cookies_list/", web_views.cookies_list, name="cookies_list"),
    path("cookies_del/", web_views.del_cookies, name="cookies_del"),
    path("excluded_url_list/", web_views.exluded_url_list, name="excluded_url_list"),
    path("del_notify/", web_views.del_notify, name="del_notify"),
    path("del_all_notify/", web_views.del_all_notify, name="del_all_notify"),

    # Dynamic scans
    path("list_vuln/", views.list_vuln, name="list_vuln"),
    path("list_scans/", views.list_scans, name="list_scans"),
    path("list_vuln_info/", views.list_vuln_info, name="list_vuln_info"),
    path("scan_details/", views.scan_details, name="scan_details"),
    path("scan_delete/", views.scan_delete, name="scan_delete"),
    path("vuln_delete/", views.vuln_delete, name="vuln_delete"),
]
