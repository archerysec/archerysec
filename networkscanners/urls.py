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
from networkscanners import views

app_name = 'networkscanners'

urlpatterns = [
    url(r'^$',
        views.index,
        name='index'),
    url(r'^vul_details/',
        views.scan_vul_details,
        name='vul_details'),
    url(r'^launch_scan',
        views.launch_scan,
        name='launch_scan'),
    url(r'^scan_del',
        views.scan_del,
        name='scan_del'),
    url(r'^ip_scan',
        views.ip_scan,
        name='ip_scan'),
    url(r'^ip_table',
        views.ip_scan_table,
        name='ip_scan_table'),
    url(r'^nv_setting',
        views.nv_setting,
        name='nv_setting'),
    url(r'^nv_details',
        views.nv_details,
        name='nv_details'),
    url(r'^openvas_setting',
        views.openvas_setting,
        name='openvas_setting'),
    url(r'^openvas_details',
        views.openvas_details,
        name='openvas_details'),
    url(r'^del_vuln',
        views.del_vuln,
        name='del_vuln'),
    url(r'^edit_vuln',
        views.edit_vuln,
        name='edit_vuln'),
    url(r'^vuln_check',
        views.vuln_check,
        name='vuln_check'),
    url(r'^add_vuln',
        views.add_vuln,
        name='add_vuln'),
    url(r'^OpenVAS_xml_upload',
        views.OpenVAS_xml_upload,
        name='OpenVAS_xml_upload'),
    url(r'^net_scan_schedule',
        views.net_scan_schedule,
        name='net_scan_schedule'),
    url(r'^del_net_scan_schedule',
        views.del_net_scan_schedule,
        name='del_net_scan_schedule'),

    url(r'^nessus_scan',
        views.nessus_scan,
        name='nessus_scan'),
    url(r'^nessus_vuln_details',
        views.nessus_vuln_details,
        name='nessus_vuln_details'),
    url(r'^delete_nessus_scan',
        views.delete_nessus_scan,
        name='delete_nessus_scan'),
    url(r'^nessus_vuln_check',
        views.nessus_vuln_check,
        name='nessus_vuln_check'),
    url(r'^delete_nessus_vuln',
        views.delete_nessus_vuln,
        name='delete_nessus_vuln'),
]
