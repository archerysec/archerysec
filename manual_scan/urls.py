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
from manual_scan import views
from django.conf import settings
from django.conf.urls.static import static

app_name = 'manual_scan'

urlpatterns = [
    path('',
        views.list_scan,
        name='list_scan'),
    path('add_vuln/',
        views.add_vuln,
        name='add_vuln'),
    path('vuln_list/',
        views.vuln_list,
        name='vuln_list'),
    path('edit_vuln/',
        views.edit_vuln,
        name='edit_vuln'),
    path('manual_vuln_data/',
        views.manual_vuln_data,
        name='manual_vuln_data'),
    path('del_vuln/',
        views.del_vuln,
        name='del_vuln'),
    path('del_scan/',
        views.del_scan,
        name='del_scan'),
    path('vuln_details/',
        views.vuln_details,
        name='vuln_details'),
    path('add_list_scan/',
        views.add_list_scan,
        name='add_list_scan'),

    path('add_vuln_data/',
        views.add_vuln_data,
        name='add_vuln_data'),

    path('add_new_vuln/',
        views.add_new_vuln,
        name='add_new_vuln'),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
