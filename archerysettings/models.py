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

from __future__ import unicode_literals

from django.db import models


class zap_settings_db(models.Model):
    zap_url = models.TextField(blank=False, null=False, default='127.0.0.1')
    zap_api = models.TextField(blank=False, null=False, default='dwed23wdwedwwefw4rwrfw')
    zap_port = models.IntegerField(blank=False, null=False, default=8090)
    enabled = models.BooleanField(blank=False, null=False)
    username = models.CharField(max_length=256, null=True)


class arachni_settings_db(models.Model):
    arachni_url = models.TextField(blank=True, null=True)
    arachni_port = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)


class burp_setting_db(models.Model):
    burp_url = models.TextField(blank=True, null=True)
    burp_port = models.TextField(blank=True, null=True)
    burp_api_key = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)


class openvas_setting_db(models.Model):
    host = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=False, null=False, default=9390)
    enabled = models.BooleanField(blank=False, null=False)
    user = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)


class nmap_vulners_setting_db(models.Model):
    enabled = models.BooleanField(blank=False, null=False)
    # -sV | Version detection
    version = models.BooleanField(blank=False, null=False)
    # -Pn | Treat all hosts as online -- skip host discovery
    online = models.BooleanField(blank=False, null=False)
    # -T4 | Set timing template (higher is faster)
    timing = models.IntegerField(blank=False, null=False, default=0)
    username = models.CharField(max_length=256, null=True)


class email_db(models.Model):
    subject = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    recipient_list = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
