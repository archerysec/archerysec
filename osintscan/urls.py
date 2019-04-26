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

from django.conf.urls import url
from osintscan import views

app_name = 'osintscan'

urlpatterns = [
    url(r'^domain_osint/$',
        views.domain_osint,
        name='domain_osint'),
    url(r'^sub_domain_search/$',
        views.sub_domain_search,
        name='sub_domain_search'),
    url(r'^domain_list/$',
        views.domain_list,
        name='domain_list'),
    url(r'^del_sub_domain/$',
        views.del_sub_domain,
        name='del_sub_domain'),
    url(r'^osint_whois/$',
        views.osint_whois,
        name='osint_whois'),
    url(r'^whois_info/$',
        views.whois_info,
        name='whois_info'),
    url(r'^del_osint_domain/$',
        views.del_osint_domain,
        name='del_osint_domain'),

]
