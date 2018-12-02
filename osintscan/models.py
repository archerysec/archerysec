# -*- coding: utf-8 -*-
#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
#/_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

from django.db import models


class osint_domain_db(models.Model):
    domains = models.TextField(blank=True, null=True)
    sub_domains = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)


class osint_whois_db(models.Model):
    domain = models.TextField(blank=True, null=True)
    updated_date = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    city = models.TextField(blank=True, null=True)
    expiration_date = models.TextField(blank=True, null=True)
    zipcode = models.TextField(blank=True, null=True)
    domain_name = models.TextField(blank=True, null=True)
    country = models.TextField(blank=True, null=True)
    whois_server = models.TextField(blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    registrar = models.TextField(blank=True, null=True)
    referral_url = models.TextField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    name_servers = models.TextField(blank=True, null=True)
    org = models.TextField(blank=True, null=True)
    creation_date = models.TextField(blank=True, null=True)
    emails = models.TextField(blank=True, null=True)