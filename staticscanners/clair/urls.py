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
from staticscanners.clair import views

urlpatterns = [
    # Bandit scan list

    url(r'^clair_list',
        views.clair_list,
        name='clair_list'),

    url(r'^clair_all_vuln',
        views.list_vuln,
        name='clair_all_vuln'),

    url(r'^clair_vuln_data',
        views.clair_vuln_data,
        name='clair_vuln_data'),

    url(r'^clair_details',
        views.clair_details,
        name='clair_details'),

    url(r'^del_clair',
        views.del_clair,
        name='del_clair'),

    url(r'^clair_del_vuln',
        views.clair_del_vuln,
        name='clair_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
