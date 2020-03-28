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
from jiraticketing import views

app_name = 'jiraticketing'

urlpatterns = [
    url(r'^jira_setting/$',
        views.jira_setting,
        name='jira_setting'),
    url(r'^submit_jira_ticket/$',
        views.submit_jira_ticket,
        name='submit_jira_ticket'),

]
