#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
#/_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from django.conf.urls import url
from . import views

app_name = 'APIScan'

urlpatterns = [
    url(r'^$', views.api__scans, name='listscan'),
    url(r'^scanapi/$', views.list_api_scan, name='listscan'),
    url(r'^create/$', views.add_api_scan, name='addapiscan'),
    url(r'^del_scan/$', views.del_api_scan, name='del_scan'),
    url(r'^api_scan_auth/$', views.authenticate, name='authenticate'),
    url(r'^api_scan_url/$', views.url_api_scan, name='api_scan_url'),
    url(r'^api_scan_edit/$', views.edit_scan, name='api_scan_edit'),
    url(r'^api_scans/$', views.api__scans, name='api_scans'),
    url(r'^add_scan/$', views.add_scan, name='add_Scan'),
    url(r'^del_scans/$', views.del_scans, name='del_Scans'),

]
