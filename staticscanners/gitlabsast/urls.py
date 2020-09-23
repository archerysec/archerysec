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
from staticscanners.gitlabsast import views

app_name = 'gitlabsast'

urlpatterns = [
    # Bandit scan list

    url(r'^gitlabsast_list',
        views.gitlabsast_list,
        name='gitlabsast_list'),

    url(r'^gitlabsast_all_vuln',
        views.list_vuln,
        name='gitlabsast_all_vuln'),

    url(r'^gitlabsast_vuln_data',
        views.gitlabsast_vuln_data,
        name='gitlabsast_vuln_data'),

    url(r'^gitlabsast_details',
        views.gitlabsast_details,
        name='gitlabsast_details'),

    url(r'^del_gitlabsast',
        views.del_gitlabsast,
        name='del_gitlabsast'),

    url(r'^gitlabsast_del_vuln',
        views.gitlabsast_del_vuln,
        name='gitlabsast_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
