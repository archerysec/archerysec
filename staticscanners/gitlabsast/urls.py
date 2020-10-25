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
from staticscanners.gitlabsast import views

app_name = 'gitlabsast'

urlpatterns = [
    # Bandit scan list

    path('gitlabsast_list',
        views.gitlabsast_list,
        name='gitlabsast_list'),

    path('gitlabsast_all_vuln',
        views.list_vuln,
        name='gitlabsast_all_vuln'),

    path('gitlabsast_vuln_data',
        views.gitlabsast_vuln_data,
        name='gitlabsast_vuln_data'),

    path('gitlabsast_details',
        views.gitlabsast_details,
        name='gitlabsast_details'),

    path('del_gitlabsast',
        views.del_gitlabsast,
        name='del_gitlabsast'),

    path('gitlabsast_del_vuln',
        views.gitlabsast_del_vuln,
        name='gitlabsast_del_vuln'),
    path('export',
        views.export,
        name='export'),
]
