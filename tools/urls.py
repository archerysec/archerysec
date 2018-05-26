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
from tools import views

app_name = 'tools'

urlpatterns = [
    url(r'^sslscan/$',
        views.sslscan,
        name='sslscan'),
    url(r'^sslscan_result/$',
        views.sslscan_result,
        name='sslscan_result'),
    url(r'^sslcan_del/$',
        views.sslcan_del,
        name='sslcan_del'),

    # Nikto requests
    url(r'^nikto/$',
        views.nikto,
        name='nikto'),
    url(r'^nikto_result/$',
        views.nikto_result,
        name='nikto_result'),
    url(r'^nikto_scan_del/$',
        views.nikto_scan_del,
        name='nikto_scan_del'),
]
