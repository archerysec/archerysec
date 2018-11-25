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
from staticscanners.dependencycheck import views

urlpatterns = [
    # Bandit scan list
    url(r'^dependencycheck_list',
        views.dependencycheck_list,
        name='dependencycheck_list'),

    url(r'^dependencycheck_all_vuln',
        views.list_vuln,
        name='dependencycheck_all_vuln'),

    url(r'^dependencycheck_vuln_data',
        views.dependencycheck_vuln_data,
        name='dependencycheck_vuln_data'),

    url(r'^dependencycheck_details',
        views.dependencycheck_details,
        name='dependencycheck_details'),

    url(r'^del_dependencycheck',
        views.del_dependencycheck,
        name='del_dependencycheck'),

    url(r'^dependencycheck_del_vuln',
        views.dependencycheck_del_vuln,
        name='dependencycheck_del_vuln'),
]
