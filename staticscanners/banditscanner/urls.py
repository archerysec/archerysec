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
from staticscanners.banditscanner import views

app_name = 'banditscanner'

urlpatterns = [
    # Bandit scan list
    path('banditscans_list/',
        views.banditscans_list,
        name='banditscans_list'),

    path('banditscan_list_vuln/',
        views.banditscan_list_vuln,
        name='banditscan_list_vuln'),

    path('banditscan_vuln_data/',
        views.banditscan_vuln_data,
        name='banditscan_vuln_data'),

    path('banditscan_details/',
        views.banditscan_details,
        name='banditscan_details'),

    path('del_bandit_scan/',
        views.del_bandit_scan,
        name='del_bandit_scan'),

    path('bandit_del_vuln/',
        views.bandit_del_vuln,
        name='bandit_del_vuln'),
]
