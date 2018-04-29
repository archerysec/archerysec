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
    url(r'^OpenVas_xml_upload',
        views.OpenVas_xml_upload,
        name='OpenVas_xml_upload'),
    url(r'^net_scan_schedule',
        views.net_scan_schedule,
        name='net_scan_schedule'),
    url(r'^del_web_scan_schedule',
        views.del_web_scan_schedule,
        name='del_web_scan_schedule'),
]
