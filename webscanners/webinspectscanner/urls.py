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
from webscanners.webinspectscanner import views

app_name = 'webinspectscanner'

urlpatterns = [

    # All webinspect URL's
    path('webinspect_list_vuln',
        views.webinspect_list_vuln,
        name='webinspect_list_vuln'),
    path('webinspect_scan_list',
        views.webinspect_scan_list,
        name='webinspect_scan_list'),
    path('webinspect_vuln_data',
        views.webinspect_vuln_data,
        name='webinspect_vuln_data'),
    path('webinspect_vuln_out',
        views.webinspect_vuln_out,
        name='webinspect_vuln_out'),
    path('del_webinspect_scan',
        views.del_webinspect_scan,
        name='del_webinspect_scan'),
    path('webinspect_del_vuln',
        views.webinspect_del_vuln,
        name='webinspect_del_vuln'),
    path('export',
        views.export,
        name='export'),

]
