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
from staticscanners.findbugs import views

app_name = 'findbugs'

urlpatterns = [
    # Bandit scan list

    path('findbugs_list/',
        views.findbugs_list,
        name='findbugs_list'),

    path('findbugs_all_vuln/',
        views.list_vuln,
        name='findbugs_all_vuln'),

    path('findbugs_vuln_data/',
        views.findbugs_vuln_data,
        name='findbugs_vuln_data'),

    path('findbugs_details/',
        views.findbugs_details,
        name='findbugs_details'),

    path('del_findbugs/',
        views.del_findbugs,
        name='del_findbugs'),

    path('findbugs_del_vuln/',
        views.findbugs_del_vuln,
        name='findbugs_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
