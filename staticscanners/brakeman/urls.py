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
from staticscanners.brakeman import views
 
app_name = 'brakeman'
 
urlpatterns = [
    # brakeman scan list
 
    path('brakeman_list/',
        views.brakeman_list,
        name='brakeman_list'),
 
    path('brakeman_all_vuln/',
        views.list_vuln,
        name='brakeman_all_vuln'),
 
    path('brakeman_vuln_data/',
        views.brakeman_vuln_data,
        name='brakeman_vuln_data'),
 
    path('brakeman_details/',
        views.brakeman_details,
        name='brakeman_details'),
 
    path('del_brakeman/',
        views.del_brakeman,
        name='del_brakeman'),
 
    path('brakeman_del_vuln/',
        views.brakeman_del_vuln,
        name='brakeman_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
