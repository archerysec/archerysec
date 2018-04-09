#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from django.conf.urls import url
from Dashboard import views
from webscanners import web_views

app_name = 'Dashboard'

urlpatterns = [

    url(r'^login/$',
        web_views.login,
        name='login'),
    url(r'^auth/$',
        web_views.auth_view,
        name='auth'),
    url(r'^logout/$',
        web_views.logout,
        name='logout'),
    url(r'^loggedin/$',
        web_views.loggedin,
        name='loggedin'),
    url(r'^signup/$',
        web_views.signup,
        name='signup'),

    url(r'^$',
        views.dash_call,
        name='zap_vuln_chart'),
    url(r'^dashboard/$',
        views.dash_call,
        name='dashboard'),
    url(r'^project_dashboard/$',
        views.project_dashboard,
        name='project_dashboard'),
    url(r'^web_dashboard/$',
        views.web_dashboard,
        name='web_dashboard'),
    url(r'^net_dashboard/$',
        views.net_dashboard,
        name='net_dashboard'),
    url(r'^proj_data/$',
        views.proj_data,
        name='proj_data'),
    url(r'^web_dash_data/$',
        views.web_dash_data,
        name='web_dash_data'),
    url(r'^net_dash_data/$',
        views.net_dash_data,
        name='net_dash_data'),
    url(r'^vuln_stat_dash/$',
        views.vuln_static_dashboard,
        name='vuln_stat_dash')

]
