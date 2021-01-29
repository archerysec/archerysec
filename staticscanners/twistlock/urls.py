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
from staticscanners.twistlock import views
 
app_name = 'twistlock'
 
urlpatterns = [
    # twistlock scan list
 
    path('twistlock_list/',
        views.twistlock_list,
        name='twistlock_list'),
 
    path('twistlock_all_vuln/',
        views.list_vuln,
        name='twistlock_all_vuln'),
 
    path('twistlock_vuln_data/',
        views.twistlock_vuln_data,
        name='twistlock_vuln_data'),
 
    path('twistlock_details/',
        views.twistlock_details,
        name='twistlock_details'),
 
    path('del_twistlock/',
        views.del_twistlock,
        name='del_twistlock'),
 
    path('twistlock_del_vuln/',
        views.twistlock_del_vuln,
        name='twistlock_del_vuln'),
    path('export/',
        views.export,
        name='export'),
]
