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
from dashboard import views
from webscanners import web_views

app_name = 'dashboard'

urlpatterns = [

    path('login/',
        web_views.login,
        name='login'),
    path('auth/',
        web_views.auth_view,
        name='auth'),
    path('logout/',
        web_views.logout,
        name='logout'),
    path('loggedin/',
        web_views.loggedin,
        name='loggedin'),
    path('signup/',
        web_views.signup,
        name='signup'),

    path('',
        views.dashboard,
        name='dashboard'),
    path('dashboard/',
        views.dashboard,
        name='dashboard'),
    path('project_dashboard/',
        views.project_dashboard,
        name='project_dashboard'),
    path('proj_data/',
        views.proj_data,
        name='proj_data'),
    path('all_high_vuln/',
        views.all_high_vuln,
        name='all_high_vuln'),
    path('export/',
        views.export,
        name='export')


]
