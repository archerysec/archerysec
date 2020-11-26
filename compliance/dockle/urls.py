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
from compliance.dockle import views

app_name = 'dockle'

urlpatterns = [
    # Bandit scan list

    path('dockle_list/',
        views.dockle_list,
        name='dockle_list'),

    path('dockle_all_vuln/',
        views.list_vuln,
        name='dockle_all_vuln'),

    path('dockle_vuln_data/',
        views.dockle_vuln_data,
        name='dockle_vuln_data'),

    path('dockle_details/',
        views.dockle_details,
        name='dockle_details'),

    path('del_dockle/',
        views.del_dockle,
        name='del_dockle'),

    path('dockle_del_vuln/',
        views.dockle_del_vuln,
        name='dockle_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
