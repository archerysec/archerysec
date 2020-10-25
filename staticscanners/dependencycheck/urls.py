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
from staticscanners.dependencycheck import views

app_name = 'dependencycheck'

urlpatterns = [
    # Bandit scan list
    path('dependencycheck_list/',
        views.dependencycheck_list,
        name='dependencycheck_list'),

    path('dependencycheck_all_vuln/',
        views.list_vuln,
        name='dependencycheck_all_vuln'),

    path('dependencycheck_vuln_data/',
        views.dependencycheck_vuln_data,
        name='dependencycheck_vuln_data'),

    path('dependencycheck_details/',
        views.dependencycheck_details,
        name='dependencycheck_details'),

    path('del_dependencycheck/',
        views.del_dependencycheck,
        name='del_dependencycheck'),

    path('dependencycheck_del_vuln/',
        views.dependencycheck_del_vuln,
        name='dependencycheck_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
