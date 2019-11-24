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
from staticscanners.trivy import views

app_name = 'trivy'

urlpatterns = [
    # Bandit scan list

    url(r'^trivy_list',
        views.trivy_list,
        name='trivy_list'),

    url(r'^trivy_all_vuln',
        views.list_vuln,
        name='trivy_all_vuln'),

    url(r'^trivy_vuln_data',
        views.trivy_vuln_data,
        name='trivy_vuln_data'),

    url(r'^trivy_details',
        views.trivy_details,
        name='trivy_details'),

    url(r'^del_trivy',
        views.del_trivy,
        name='del_trivy'),

    url(r'^trivy_del_vuln',
        views.trivy_del_vuln,
        name='trivy_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
