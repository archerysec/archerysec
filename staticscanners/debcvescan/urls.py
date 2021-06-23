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

from django.urls import path
from staticscanners.debcvescan import views

app_name = 'debcvescan'

urlpatterns = [

    path('debcvescan_list/',
        views.debcvescan_list,
        name='debcvescan_list'),

    path('debcvescan_all_vuln/',
        views.list_vuln,
        name='debcvescan_all_vuln'),

    path('debcvescan_vuln_data/',
        views.debcvescan_vuln_data,
        name='debcvescan_vuln_data'),

    path('debcvescan_details/',
        views.debcvescan_details,
        name='gdebcvescan_details'),

    path('del_debcvescan/',
        views.del_debcvescan,
        name='del_debcvescan'),

    path('debcvescan_del_vuln/',
         views.debcvescan_del_vuln,
         name='debcvescan_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
