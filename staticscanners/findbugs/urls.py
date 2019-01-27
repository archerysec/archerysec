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
from staticscanners.findbugs import views

urlpatterns = [
    # Bandit scan list

    url(r'^findbugs_list',
        views.findbugs_list,
        name='findbugs_list'),

    url(r'^findbugs_all_vuln',
        views.list_vuln,
        name='findbugs_all_vuln'),

    url(r'^findbugs_vuln_data',
        views.findbugs_vuln_data,
        name='findbugs_vuln_data'),

    url(r'^findbugs_details',
        views.findbugs_details,
        name='findbugs_details'),

    url(r'^del_findbugs',
        views.del_findbugs,
        name='del_findbugs'),

    url(r'^findbugs_del_vuln',
        views.findbugs_del_vuln,
        name='findbugs_del_vuln'),
    url(r'^export',
        views.export,
        name='export'),
]
