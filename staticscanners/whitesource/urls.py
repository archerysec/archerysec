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
from staticscanners.whitesource import views

app_name = 'whitesource'

urlpatterns = [
    # Bandit scan list

    url(r'^whitesource_list',
        views.whitesource_list,
        name='whitesource_list'),

    url(r'^whitesource_all_vuln',
        views.list_vuln,
        name='whitesource_all_vuln'),

    url(r'^whitesource_vuln_data',
        views.whitesource_vuln_data,
        name='whitesource_vuln_data'),

    url(r'^whitesource_details',
        views.whitesource_details,
        name='whitesource_details'),

    url(r'^del_whitesource',
        views.del_whitesource,
        name='del_whitesource'),

    url(r'^whitesource_del_vuln',
        views.whitesource_del_vuln,
        name='whitesource_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
