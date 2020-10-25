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
from staticscanners.tfsec import views

app_name = 'tfsec'

urlpatterns = [
    # Bandit scan list

    path('tfsec_list',
        views.tfsec_list,
        name='tfsec_list'),

    path('tfsec_all_vuln',
        views.list_vuln,
        name='tfsec_all_vuln'),

    path('tfsec_vuln_data',
        views.tfsec_vuln_data,
        name='tfsec_vuln_data'),

    path('tfsec_details',
        views.tfsec_details,
        name='tfsec_details'),

    path('del_tfsec',
        views.del_tfsec,
        name='del_tfsec'),

    path('tfsec_del_vuln',
        views.tfsec_del_vuln,
        name='tfsec_del_vuln'),
    path('export',
        views.export,
        name='export'),
]
