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
from webscanners.arachniscanner import views

urlpatterns = [

    # arachni
    url(r'^arachni_list_vuln',
        views.arachni_list_vuln,
        name='arachni_list_vuln'),
    url(r'^arachni_scan_list',
        views.arachni_scan_list,
        name='arachni_scan_list'),
    url(r'^arachni_vuln_data',
        views.arachni_vuln_data,
        name='arachni_vuln_data'),
    url(r'^arachni_vuln_out',
        views.arachni_vuln_out,
        name='arachni_vuln_out'),
    url(r'^del_arachni_scan',
        views.del_arachni_scan,
        name='del_arachni_scan'),
    url(r'^arachni_del_vuln',
        views.arachni_del_vuln,
        name='arachni_del_vuln'),
    url(r'^arachni_settings/',
        views.arachni_settings,
        name='arachni_settings'),

    url(r'^arachni_setting_update/',
        views.arachni_setting_update,
        name='arachni_setting_update'),

    url(r'^arachni_scan_launch/',
        views.arachni_scan,
        name='arachni_scan_launch'),

]
