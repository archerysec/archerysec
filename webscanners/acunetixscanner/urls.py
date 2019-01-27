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
from webscanners.acunetixscanner import views

urlpatterns = [
    # All acunetix URL's
    url(r'^acunetix_list_vuln',
        views.acunetix_list_vuln,
        name='acunetix_list_vuln'),
    url(r'^acunetix_scan_list',
        views.acunetix_scan_list,
        name='acunetix_scan_list'),
    url(r'^acunetix_vuln_data',
        views.acunetix_vuln_data,
        name='acunetix_vuln_data'),
    url(r'^acunetix_vuln_out',
        views.acunetix_vuln_out,
        name='acunetix_vuln_out'),
    url(r'^del_acunetix_scan',
        views.del_acunetix_scan,
        name='del_acunetix_scan'),
    url(r'^acunetix_del_vuln',
        views.acunetix_del_vuln,
        name='acunetix_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),

]
