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
from webscanners.netsparkerscanner import views

urlpatterns = [
    # All netsparker URL's
    url(r'^netsparker_list_vuln',
        views.netsparker_list_vuln,
        name='netsparker_list_vuln'),
    url(r'^netsparker_scan_list',
        views.netsparker_scan_list,
        name='netsparker_scan_list'),
    url(r'^netsparker_vuln_data',
        views.netsparker_vuln_data,
        name='netsparker_vuln_data'),
    url(r'^netsparker_vuln_out',
        views.netsparker_vuln_out,
        name='netsparker_vuln_out'),
    url(r'^del_netsparker_scan',
        views.del_netsparker_scan,
        name='del_netsparker_scan'),
    url(r'^netsparker_del_vuln',
        views.netsparker_del_vuln,
        name='netsparker_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),

]
