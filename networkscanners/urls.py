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
from networkscanners import views

app_name = 'networkscanners'

urlpatterns = [
    path('',
        views.index,
        name='index'),
    path('vul_details/',
        views.scan_vul_details,
        name='vul_details'),
    path('launch_scan',
        views.launch_scan,
        name='launch_scan'),
    path('scan_del',
        views.scan_del,
        name='scan_del'),
    path('ip_scan',
        views.ip_scan,
        name='ip_scan'),
    path('nv_setting',
        views.nv_setting,
        name='nv_setting'),
    path('nv_details',
        views.nv_details,
        name='nv_details'),
    path('openvas_setting',
        views.openvas_setting,
        name='openvas_setting'),
    path('openvas_details',
        views.openvas_details,
        name='openvas_details'),
    path('del_vuln',
        views.del_vuln,
        name='del_vuln'),
    path('vuln_check',
        views.vuln_check,
        name='vuln_check'),
    path('OpenVAS_xml_upload',
        views.OpenVAS_xml_upload,
        name='OpenVAS_xml_upload'),
    path('net_scan_schedule',
        views.net_scan_schedule,
        name='net_scan_schedule'),
    path('del_net_scan_schedule',
        views.del_net_scan_schedule,
        name='del_net_scan_schedule'),
]
