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


class zap_settings_db(models.Model):
    zap_url = models.TextField(blank=True, null=True)
    zap_api = models.TextField(blank=True, null=True)
    zap_port = models.TextField(blank=True, null=True)


class burp_setting_db(models.Model):
    burp_url = models.TextField(blank=True, null=True)
    burp_port = models.TextField(blank=True, null=True)


class openvas_setting_db(models.Model):
    host = models.TextField(blank=True, null=True)
    user = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
