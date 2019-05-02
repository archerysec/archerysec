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
from staticscanners.retirejsscan import views

urlpatterns = [
    # retirejs scan list
    url(r'^retirejsscans_list',
        views.retirejsscans_list,
        name='retirejsscans_list'),

    url(r'^retirejsscan_list_vuln',
        views.retirejsscan_list_vuln,
        name='retirejsscan_list_vuln'),

    url(r'^retirejsscan_vuln_data',
        views.retirejsscan_vuln_data,
        name='retirejsscan_vuln_data'),

    url(r'^retirejsscan_details',
        views.retirejsscan_details,
        name='retirejsscan_details'),

    url(r'^del_retirejs_scan',
        views.del_retirejs_scan,
        name='del_retirejs_scan'),

    url(r'^retirejs_del_vuln',
        views.retirejs_del_vuln,
        name='retirejs_del_vuln'),
]
