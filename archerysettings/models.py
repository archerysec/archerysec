# -*- coding: utf-8 -*-
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

from __future__ import unicode_literals

from django.db import models


class zap_settings_db(models.Model):
    zap_url = models.TextField(blank=True, null=True)
    zap_api = models.TextField(blank=True, null=True)
    zap_port = models.TextField(blank=True, null=True)


class arachni_settings_db(models.Model):
    arachni_url = models.TextField(blank=True, null=True)
    arachni_port = models.TextField(blank=True, null=True)


class burp_setting_db(models.Model):
    burp_url = models.TextField(blank=True, null=True)
    burp_port = models.TextField(blank=True, null=True)


class openvas_setting_db(models.Model):
    host = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=9390, null=9390)
    enabled = models.NullBooleanField(blank=False, null=False)
    user = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)


class nmap_vulners_setting_db(models.Model):
    enabled = models.NullBooleanField(blank=False, null=False)
    # -sV | Version detection
    version = models.NullBooleanField(blank=False, null=False)
    # -Pn | Treat all hosts as online -- skip host discovery
    online = models.NullBooleanField(blank=False, null=False)
    # -T4 | Set timing template (higher is faster)
    timing = models.IntegerField(blank=0, null=0)
