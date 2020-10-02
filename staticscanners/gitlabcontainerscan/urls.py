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
from staticscanners.gitlabcontainerscan import views

app_name = 'gitlabcontainerscan'

urlpatterns = [
    # Bandit scan list

    url(r'^gitlabcontainerscan_list',
        views.gitlabcontainerscan_list,
        name='gitlabcontainerscan_list'),

    url(r'^gitlabcontainerscan_all_vuln',
        views.list_vuln,
        name='gitlabcontainerscan_all_vuln'),

    url(r'^gitlabcontainerscan_vuln_data',
        views.gitlabcontainerscan_vuln_data,
        name='gitlabcontainerscan_vuln_data'),

    url(r'^gitlabcontainerscan_details',
        views.gitlabcontainerscan_details,
        name='gitlabcontainerscan_details'),

    url(r'^del_gitlabcontainerscan',
        views.del_gitlabcontainerscan,
        name='del_gitlabcontainerscan'),

    url(r'^gitlabcontainerscan_del_vuln',
        views.gitlabcontainerscan_del_vuln,
        name='gitlabcontainerscan_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
