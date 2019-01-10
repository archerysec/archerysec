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

    url(r'^nikto_result_vul/$',
        views.nikto_result_vul,
        name='nikto_result_vul'),
    url(r'^nikto_vuln_del/$',
        views.nikto_vuln_del,
        name='nikto_vuln_del'),

    # nmap requests
    url(r'^nmap_scan/$',
        views.nmap_scan,
        name='nmap_scan'),
    url(r'^nmap/$',
        views.nmap,
        name='nmap'),
    url(r'^nmap_result/$',
        views.nmap_result,
        name='nmap_result'),
    url(r'^nmap_scan_del/$',
        views.nmap_scan_del,
        name='nmap_scan_del'),

    #Nmap_Vulners
    url(r'^nmap_vulners_scan/$',
        views.nmap_vulners_scan,
        name='nmap_scan'),
    url(r'^nmap_vulners/$',
        views.nmap_vulners,
        name='nmap_vulners'),
    url(r'^nmap_vulners_port_list/$',
        views.nmap_vulners_port,
        name='nmap_vulners_port'),
]
