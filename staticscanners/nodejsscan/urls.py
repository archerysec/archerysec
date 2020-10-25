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
from staticscanners.nodejsscan import views

app_name = 'nodejsscan'

urlpatterns = [
    # Bandit scan list

    path('nodejsscan_list/',
        views.nodejsscan_list,
        name='nodejsscan_list'),

    path('nodejsscan_all_vuln/',
        views.list_vuln,
        name='nodejsscan_all_vuln'),

    path('nodejsscan_vuln_data/',
        views.nodejsscan_vuln_data,
        name='nodejsscan_vuln_data'),

    path('nodejsscan_details/',
        views.nodejsscan_details,
        name='nodejsscan_details'),

    path('del_nodejsscan/',
        views.del_nodejsscan,
        name='del_nodejsscan'),

    path('nodejsscan_del_vuln/',
        views.nodejsscan_del_vuln,
        name='nodejsscan_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
