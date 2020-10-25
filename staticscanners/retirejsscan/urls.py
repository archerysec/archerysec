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
from staticscanners.retirejsscan import views


app_name = 'retirejsscan'

urlpatterns = [
    # retirejs scan list
    path('retirejsscans_list',
        views.retirejsscans_list,
        name='retirejsscans_list'),

    path('retirejsscan_list_vuln',
        views.retirejsscan_list_vuln,
        name='retirejsscan_list_vuln'),

    path('retirejsscan_vuln_data',
        views.retirejsscan_vuln_data,
        name='retirejsscan_vuln_data'),

    path('retirejsscan_details',
        views.retirejsscan_details,
        name='retirejsscan_details'),

    path('del_retirejs_scan',
        views.del_retirejs_scan,
        name='del_retirejs_scan'),

    path('retirejs_del_vuln',
        views.retirejs_del_vuln,
        name='retirejs_del_vuln'),
]
