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
from staticscanners.semgrep import views

app_name = 'semgrepscan'

urlpatterns = [
    # Bandit scan list

    path('semgrepscan_list/',
        views.semgrepscan_list,
        name='semgrepscan_list'),

    path('semgrepscan_all_vuln/',
        views.list_vuln,
        name='semgrepscan_all_vuln'),

    path('semgrepscan_vuln_data/',
        views.semgrepscan_vuln_data,
        name='semgrepscan_vuln_data'),

    path('semgrepscan_details/',
        views.semgrepscan_details,
        name='semgrepscan_details'),

    path('del_semgrepscan/',
        views.del_semgrepscan,
        name='del_semgrepscan'),

    path('semgrepscan_del_vuln/',
        views.semgrepscan_del_vuln,
        name='semgrepscan_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
