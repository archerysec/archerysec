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
from staticscanners.nodejsscan import views

app_name = 'nodejsscan'

urlpatterns = [
    # Bandit scan list

    url(r'^nodejsscan_list',
        views.nodejsscan_list,
        name='nodejsscan_list'),

    url(r'^nodejsscan_all_vuln',
        views.list_vuln,
        name='nodejsscan_all_vuln'),

    url(r'^nodejsscan_vuln_data',
        views.nodejsscan_vuln_data,
        name='nodejsscan_vuln_data'),

    url(r'^nodejsscan_details',
        views.nodejsscan_details,
        name='nodejsscan_details'),

    url(r'^del_nodejsscan',
        views.del_nodejsscan,
        name='del_nodejsscan'),

    url(r'^nodejsscan_del_vuln',
        views.nodejsscan_del_vuln,
        name='nodejsscan_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
