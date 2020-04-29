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
from staticscanners.npmaudit import views

app_name = 'npmaudit'

urlpatterns = [
    # Bandit scan list

    url(r'^npmaudit_list',
        views.npmaudit_list,
        name='npmaudit_list'),

    url(r'^npmaudit_all_vuln',
        views.list_vuln,
        name='npmaudit_all_vuln'),

    url(r'^npmaudit_vuln_data',
        views.npmaudit_vuln_data,
        name='npmaudit_vuln_data'),

    url(r'^npmaudit_details',
        views.npmaudit_details,
        name='npmaudit_details'),

    url(r'^del_npmaudit',
        views.del_npmaudit,
        name='del_npmaudit'),

    url(r'^npmaudit_del_vuln',
        views.npmaudit_del_vuln,
        name='npmaudit_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
