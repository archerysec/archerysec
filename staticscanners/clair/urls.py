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
from staticscanners.clair import views

app_name = 'clair'

urlpatterns = [
    # Bandit scan list

    path('clair_list/',
        views.clair_list,
        name='clair_list'),

    path('clair_all_vuln/',
        views.list_vuln,
        name='clair_all_vuln'),

    path('clair_vuln_data/',
        views.clair_vuln_data,
        name='clair_vuln_data'),

    path('clair_details/',
        views.clair_details,
        name='clair_details'),

    path('del_clair/',
        views.del_clair,
        name='del_clair'),

    path('clair_del_vuln/',
        views.clair_del_vuln,
        name='clair_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
