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
from compliance.inspec import views

urlpatterns = [
    # Bandit scan list

    url(r'^inspec_list',
        views.inspec_list,
        name='inspec_list'),

    url(r'^inspec_all_vuln',
        views.list_vuln,
        name='inspec_all_vuln'),

    url(r'^inspec_vuln_data',
        views.inspec_vuln_data,
        name='inspec_vuln_data'),

    url(r'^inspec_details',
        views.inspec_details,
        name='inspec_details'),

    url(r'^del_inspec',
        views.del_inspec,
        name='del_inspec'),

    url(r'^inspec_del_vuln',
        views.inspec_del_vuln,
        name='inspec_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
