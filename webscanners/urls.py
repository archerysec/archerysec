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

from django.conf.urls import url
from webscanners import web_views

app_name = 'webscanners'

urlpatterns = [
    url(r'^login/$',
        web_views.login,
        name='login'),
    url(r'^signup/$',
        web_views.signup,
        name='signup'),
    url(r'^auth/$',
        web_views.auth_view,
        name='auth'),
    url(r'^logout/$',
        web_views.logout,
        name='logout'),
    url(r'^loggedin/$',
        web_views.loggedin,
        name='loggedin'),
    url(r'^$',
        web_views.index,
        name='index'),
    url(r'^setting/',
        web_views.setting,
        name='setting'),


    # Burp scans
    url(r'^xml_upload',
        web_views.xml_upload,
        name='xml_upload'),
    url(r'^email_setting',
        web_views.email_setting,
        name='email_setting', ),
    url(r'^cookie_add',
        web_views.add_cookies,
        name='add_cookies', ),

    url(r'^web_task_launch',
        web_views.web_task_launch,
        name='web_task_launch'),

    url(r'^web_scan_schedule',
        web_views.web_scan_schedule,
        name='web_scan_schedule'),

    url(r'^del_web_scan_schedule',
        web_views.del_web_scan_schedule,
        name='del_web_scan_schedule'),

    url(r'^sel_login',
        web_views.sel_login,
        name='sel'),

    url(r'save_cookie',
        web_views.save_cookie,
        name='save_cookie'),

    url(r'exclude_url',
        web_views.exclude_url,
        name='exclude_url'),

    url(r'^cookies_list',
        web_views.cookies_list),

    url(r'^cookies_del',
        web_views.del_cookies),

    url(r'^excluded_url_list',
        web_views.exluded_url_list),

    url(r'^del_notify',
        web_views.del_notify),

    url(r'^del_all_notify',
        web_views.del_all_notify),

]
