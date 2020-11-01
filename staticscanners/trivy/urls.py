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
from staticscanners.trivy import views

app_name = 'trivy'

urlpatterns = [
    # Bandit scan list

    path('trivy_list/',
        views.trivy_list,
        name='trivy_list'),

    path('trivy_all_vuln/',
        views.list_vuln,
        name='trivy_all_vuln'),

    path('trivy_vuln_data/',
        views.trivy_vuln_data,
        name='trivy_vuln_data'),

    path('trivy_details/',
        views.trivy_details,
        name='trivy_details'),

    path('del_trivy/',
        views.del_trivy,
        name='del_trivy'),

    path('trivy_del_vuln/',
        views.trivy_del_vuln,
        name='trivy_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
