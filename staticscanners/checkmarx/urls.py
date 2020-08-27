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
from staticscanners.checkmarx import views

app_name = 'checkmarx'

urlpatterns = [
    # Bandit scan list

    url(r'^checkmarx_list',
        views.checkmarx_list,
        name='checkmarx_list'),

    url(r'^checkmarx_all_vuln',
        views.list_vuln,
        name='checkmarx_all_vuln'),

    url(r'^checkmarx_vuln_data',
        views.checkmarx_vuln_data,
        name='checkmarx_vuln_data'),

    url(r'^checkmarx_details',
        views.checkmarx_details,
        name='checkmarx_details'),

    url(r'^del_checkmarx',
        views.del_checkmarx,
        name='del_checkmarx'),

    url(r'^checkmarx_del_vuln',
        views.checkmarx_del_vuln,
        name='checkmarx_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
