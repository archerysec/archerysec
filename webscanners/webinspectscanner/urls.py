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
from webscanners.webinspectscanner import views

urlpatterns = [

    # All webinspect URL's
    url(r'^webinspect_list_vuln',
        views.webinspect_list_vuln,
        name='webinspect_list_vuln'),
    url(r'^webinspect_scan_list',
        views.webinspect_scan_list,
        name='webinspect_scan_list'),
    url(r'^webinspect_vuln_data',
        views.webinspect_vuln_data,
        name='webinspect_vuln_data'),
    url(r'^webinspect_vuln_out',
        views.webinspect_vuln_out,
        name='webinspect_vuln_out'),
    url(r'^del_webinspect_scan',
        views.del_webinspect_scan,
        name='del_webinspect_scan'),
    url(r'^webinspect_del_vuln',
        views.webinspect_del_vuln,
        name='webinspect_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),

]
