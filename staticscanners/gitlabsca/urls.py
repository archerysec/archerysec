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
from staticscanners.gitlabsca import views

app_name = 'gitlabsca'

urlpatterns = [
    # Bandit scan list

    url(r'^gitlabsca_list',
        views.gitlabsca_list,
        name='gitlabsca_list'),

    url(r'^gitlabsca_all_vuln',
        views.list_vuln,
        name='gitlabsca_all_vuln'),

    url(r'^gitlabsca_vuln_data',
        views.gitlabsca_vuln_data,
        name='gitlabsca_vuln_data'),

    url(r'^gitlabsca_details',
        views.gitlabsca_details,
        name='gitlabsca_details'),

    url(r'^del_gitlabsca',
        views.del_gitlabsca,
        name='del_gitlabsca'),

    url(r'^gitlabsca_del_vuln',
        views.gitlabsca_del_vuln,
        name='gitlabsca_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
