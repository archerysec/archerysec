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
from staticscanners.banditscanner import views

urlpatterns = [
    # Bandit scan list
    url(r'^banditscans_list',
        views.banditscans_list,
        name='banditscans_list'),

    url(r'^banditscan_list_vuln',
        views.banditscan_list_vuln,
        name='banditscan_list_vuln'),

    url(r'^banditscan_vuln_data',
        views.banditscan_vuln_data,
        name='banditscan_vuln_data'),

    url(r'^banditscan_details',
        views.banditscan_details,
        name='banditscan_details'),

    url(r'^del_bandit_scan',
        views.del_bandit_scan,
        name='del_bandit_scan'),

    url(r'^bandit_del_vuln',
        views.bandit_del_vuln,
        name='bandit_del_vuln'),
]
