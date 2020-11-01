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
from staticscanners.npmaudit import views

app_name = 'npmaudit'

urlpatterns = [
    # Bandit scan list

    path('npmaudit_list/',
        views.npmaudit_list,
        name='npmaudit_list'),

    path('npmaudit_all_vuln/',
        views.list_vuln,
        name='npmaudit_all_vuln'),

    path('npmaudit_vuln_data/',
        views.npmaudit_vuln_data,
        name='npmaudit_vuln_data'),

    path('npmaudit_details/',
        views.npmaudit_details,
        name='npmaudit_details'),

    path('del_npmaudit/',
        views.del_npmaudit,
        name='del_npmaudit'),

    path('npmaudit_del_vuln/',
        views.npmaudit_del_vuln,
        name='npmaudit_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
