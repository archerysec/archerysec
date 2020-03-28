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
from manual_scan import views

app_name = 'manual_scan'

urlpatterns = [
    url(r'^$',
        views.list_scan,
        name='list_scan'),
    url(r'^add_vuln/',
        views.add_vuln,
        name='add_vuln'),
    url(r'^vuln_list/',
        views.vuln_list,
        name='vuln_list'),
    url(r'^edit_vuln/',
        views.edit_vuln,
        name='edit_vuln'),
    url(r'^del_vuln/',
        views.del_vuln,
        name='del_vuln'),
    url(r'^del_scan/',
        views.del_scan,
        name='del_scan'),
    url(r'^vuln_details/',
        views.vuln_details,
        name='vuln_details'),
    url(r'^add_list_scan/',
        views.add_list_scan,
        name='add_list_scan'),

    url(r'^add_vuln_data/',
        views.add_vuln_data,
        name='add_vuln_data'),

    url(r'^add_new_vuln/',
        views.add_new_vuln,
        name='add_new_vuln'),


]
