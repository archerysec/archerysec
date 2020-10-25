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
from webscanners.acunetixscanner import views

app_name = 'acunetixscanner'

urlpatterns = [
    # All acunetix URL's
    path('acunetix_list_vuln',
        views.acunetix_list_vuln,
        name='acunetix_list_vuln'),
    path('acunetix_scan_list',
        views.acunetix_scan_list,
        name='acunetix_scan_list'),
    path('acunetix_vuln_data',
        views.acunetix_vuln_data,
        name='acunetix_vuln_data'),
    path('acunetix_vuln_out',
        views.acunetix_vuln_out,
        name='acunetix_vuln_out'),
    path('del_acunetix_scan',
        views.del_acunetix_scan,
        name='del_acunetix_scan'),
    path('acunetix_del_vuln',
        views.acunetix_del_vuln,
        name='acunetix_del_vuln'),
    path('export',
        views.export,
        name='export'),

]
