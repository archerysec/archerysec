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
from networkscanners.nessus import views

app_name = 'nessus'

urlpatterns = [
    # Bandit scan list

    path('nessus_list/',
        views.nessus_list,
        name='nessus_list'),

    path('nessus_target_list/',
        views.nessus_target_list,
        name='nessus_target_list'),

    path('nessus_target_data/',
        views.nessus_target_data,
        name='nessus_target_data'),

    path('nessus_vuln_data/',
        views.nessus_vuln_data,
        name='nessus_vuln_data'),

    path('nessus_details/',
        views.nessus_details,
        name='nessus_details'),

    path('del_nessus/',
        views.del_nessus,
        name='del_nessus'),

    path('nessus_del_vuln/',
        views.nessus_del_vuln,
        name='nessus_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
