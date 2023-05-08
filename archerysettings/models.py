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
from user_management.models import UserProfile, Organization
from django.utils import timezone


class ZapSettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    zap_url = models.TextField(blank=False, null=False, default="127.0.0.1")
    zap_api = models.TextField(
        blank=False, null=False, default="dwed23wdwedwwefw4rwrfw"
    )
    zap_port = models.IntegerField(blank=False, null=False, default=8090)
    enabled = models.BooleanField(blank=False, null=False)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='zap_settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='zap_settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class ArachniSettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    arachni_url = models.TextField(blank=True, null=True)
    arachni_port = models.TextField(blank=True, null=True)
    arachni_user = models.TextField(blank=True, null=True)
    arachni_pass = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(auto_now=True, blank=True)
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='arachni_settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='arachni_settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class BurpSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    burp_url = models.TextField(blank=True, null=True)
    burp_port = models.TextField(blank=True, null=True)
    burp_api_key = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='burp_settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='burp_settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class OpenvasSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    host = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=False, null=False, default=9390)
    enabled = models.BooleanField(blank=False, null=False)
    user = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='openvas_settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='openvas_settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class NmapVulnersSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    enabled = models.BooleanField(blank=False, null=False)
    # -sV | Version detection
    version = models.BooleanField(blank=False, null=False)
    # -Pn | Treat all hosts as online -- skip host discovery
    online = models.BooleanField(blank=False, null=False)
    # -T4 | Set timing template (higher is faster)
    timing = models.IntegerField(blank=False, null=False, default=0)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='nmap_vulner_settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='nmap_vulner_settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class EmailDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    subject = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    recipient_list = models.TextField(blank=True)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='email_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='email_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class SettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    setting_name = models.TextField(blank=True, null=True)
    setting_scanner = models.TextField(blank=True, null=True)
    setting_status = models.BooleanField(blank=True, null=True)
    created_time = models.DateTimeField(auto_now=True, blank=True, )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='settings_db_created'
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='settings_db_updated'
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)
