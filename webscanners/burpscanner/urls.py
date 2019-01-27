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
from webscanners.burpscanner import views

urlpatterns = [
    # Burp scans
    url(r'^burp_launch_scan',
        views.burp_scan_launch,
        name='burp_scan_launch'),

    url(r'^burp_scan_list',
        views.burp_scan_list,
        name='burp_scan_list'),

    url(r'^burp_vuln_list',
        views.burp_list_vuln,
        name='burp_vuln_list'),

    url(r'^burp_vuln_data',
        views.burp_vuln_data,
        name='burp_vuln_data'),

    url(r'^burp_vuln_out',
        views.burp_vuln_out,
        name='burp_vuln_out'),

    url(r'^del_burp_scan',
        views.del_burp_scan,
        name='del_burp_scan'),

    url(r'^del_burp_vuln',
        views.del_burp_vuln,
        name='del_burp_vuln'),

    url(r'^edit_burp_vuln',
        views.edit_burp_vuln,
        name='edit_burp_vuln'),

    url(r'^export',
        views.export,
        name='export'),

]
