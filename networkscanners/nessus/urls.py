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
from networkscanners.nessus import views

app_name = 'nessus'

urlpatterns = [
    # Bandit scan list

    url(r'^nessus_list',
        views.nessus_list,
        name='nessus_list'),

    url(r'^nessus_target_list',
        views.nessus_target_list,
        name='nessus_target_list'),

    url(r'^nessus_target_data',
        views.nessus_target_data,
        name='nessus_target_data'),

    url(r'^nessus_vuln_data',
        views.nessus_vuln_data,
        name='nessus_vuln_data'),

    url(r'^nessus_details',
        views.nessus_details,
        name='nessus_details'),

    url(r'^del_nessus',
        views.del_nessus,
        name='del_nessus'),

    url(r'^nessus_del_vuln',
        views.nessus_del_vuln,
        name='nessus_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
