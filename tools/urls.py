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

from tools import views

app_name = "tools"

urlpatterns = [
    path("sslscan/", views.sslscan, name="sslscan"),
    path("sslscan_result/", views.sslscan_result, name="sslscan_result"),
    path("sslcan_del/", views.sslcan_del, name="sslcan_del"),
    # Nikto requests
    path("nikto/", views.nikto, name="nikto"),
    path("nikto_result/", views.nikto_result, name="nikto_result"),
    path("nikto_scan_del/", views.nikto_scan_del, name="nikto_scan_del"),
    path("nikto_result_vul/", views.nikto_result_vul, name="nikto_result_vul"),
    path("nikto_vuln_del/", views.nikto_vuln_del, name="nikto_vuln_del"),
    # nmap requests
    path("nmap_scan/", views.nmap_scan, name="nmap_scan"),
    path("nmap/", views.nmap, name="nmap"),
    path("nmap_result/", views.nmap_result, name="nmap_result"),
    path("nmap_scan_del/", views.nmap_scan_del, name="nmap_scan_del"),
    # Nmap_Vulners
    path("nmap_vulners_scan/", views.nmap_vulners_scan, name="nmap_scan"),
    path("nmap_vulners/", views.nmap_vulners, name="nmap_vulners"),
    path("nmap_vulners_port_list/", views.nmap_vulners_port, name="nmap_vulners_port"),
]
