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
from webscanners.arachniscanner import views

app_name = 'arachniscanner'

urlpatterns = [

    # arachni
    path('arachni_list_vuln',
        views.arachni_list_vuln,
        name='arachni_list_vuln'),
    path('arachni_scan_list',
        views.arachni_scan_list,
        name='arachni_scan_list'),
    path('arachni_vuln_data',
        views.arachni_vuln_data,
        name='arachni_vuln_data'),
    path('arachni_vuln_out',
        views.arachni_vuln_out,
        name='arachni_vuln_out'),
    path('del_arachni_scan',
        views.del_arachni_scan,
        name='del_arachni_scan'),
    path('arachni_del_vuln',
        views.arachni_del_vuln,
        name='arachni_del_vuln'),
    path('arachni_settings/',
        views.arachni_settings,
        name='arachni_settings'),

    path('arachni_setting_update/',
        views.arachni_setting_update,
        name='arachni_setting_update'),

    path('arachni_scan_launch/',
        views.arachni_scan,
        name='arachni_scan_launch'),
    path('export',
        views.export,
        name='export'),

]
