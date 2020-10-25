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
from staticscanners.gitlabcontainerscan import views

app_name = 'gitlabcontainerscan'

urlpatterns = [
    # Bandit scan list

    path('gitlabcontainerscan_list',
        views.gitlabcontainerscan_list,
        name='gitlabcontainerscan_list'),

    path('gitlabcontainerscan_all_vuln',
        views.list_vuln,
        name='gitlabcontainerscan_all_vuln'),

    path('gitlabcontainerscan_vuln_data',
        views.gitlabcontainerscan_vuln_data,
        name='gitlabcontainerscan_vuln_data'),

    path('gitlabcontainerscan_details',
        views.gitlabcontainerscan_details,
        name='gitlabcontainerscan_details'),

    path('del_gitlabcontainerscan',
        views.del_gitlabcontainerscan,
        name='del_gitlabcontainerscan'),

    path('gitlabcontainerscan_del_vuln',
        views.gitlabcontainerscan_del_vuln,
        name='gitlabcontainerscan_del_vuln'),
    path('export',
        views.export,
        name='export'),
]
