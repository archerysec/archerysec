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


# Create your models here.
class APIScan_db(models.Model):
    project_id = models.UUIDField(blank=True)
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    req_header = models.TextField(blank=True)
    req_body = models.TextField(blank=True)
    method = models.CharField(blank=True, max_length=20)
    auth_url = models.CharField(blank=True, max_length=10)
    auth_token_key = models.TextField(blank=True)
    extra_vaule_auth = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)


class APIScan_url_db(models.Model):
    project_id = models.UUIDField(blank=True)
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    req_header = models.TextField(blank=True)
    req_body = models.TextField(blank=True)
    method = models.CharField(blank=True, max_length=20)
    auth_url = models.CharField(blank=True, max_length=10)
    auth_token_key = models.TextField(blank=True)
    extra_vaule_auth = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)


class api_token_db(models.Model):
    project_id = models.UUIDField(blank=True)
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    api_token = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)