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
from compliance.dockle import views

app_name = 'dockle'

urlpatterns = [
    # Bandit scan list

    url(r'^dockle_list',
        views.dockle_list,
        name='dockle_list'),

    url(r'^dockle_all_vuln',
        views.list_vuln,
        name='dockle_all_vuln'),

    url(r'^dockle_vuln_data',
        views.dockle_vuln_data,
        name='dockle_vuln_data'),

    url(r'^dockle_details',
        views.dockle_details,
        name='dockle_details'),

    url(r'^del_dockle',
        views.del_dockle,
        name='del_dockle'),

    url(r'^dockle_del_vuln',
        views.dockle_del_vuln,
        name='dockle_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
