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
from staticscanners.whitesource import views

app_name = 'whitesource'

urlpatterns = [
    # Bandit scan list

    path('whitesource_list',
        views.whitesource_list,
        name='whitesource_list'),

    path('whitesource_all_vuln',
        views.list_vuln,
        name='whitesource_all_vuln'),

    path('whitesource_vuln_data',
        views.whitesource_vuln_data,
        name='whitesource_vuln_data'),

    path('whitesource_details',
        views.whitesource_details,
        name='whitesource_details'),

    path('del_whitesource',
        views.del_whitesource,
        name='del_whitesource'),

    path('whitesource_del_vuln',
        views.whitesource_del_vuln,
        name='whitesource_del_vuln'),
    path('export',
        views.export,
        name='export'),
]
