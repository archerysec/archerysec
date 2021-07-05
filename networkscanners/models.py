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
import uuid
from fernet_fields import EncryptedTextField


class NetworkScanDb(models.Model):
    scan_id = models.UUIDField(blank=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    critical_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    info_vul = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)
    rescan = models.TextField(blank=True, null=True)
    total_dup = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)
    scanner = models.CharField(max_length=256, null=True)


class NetworkScanResultsDb(models.Model):
    scan_id = models.UUIDField(blank=True)
    project_id = models.UUIDField(null=True)
    vuln_id = models.UUIDField(blank=True)
    title = models.TextField(blank=True)
    date_time = models.DateTimeField(blank=True, null=True)
    severity_color = models.CharField(max_length=256, null=True)
    severity = models.CharField(max_length=256, null=True)
    description = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    scanner = models.TextField()
    username = models.CharField(max_length=256, null=True)
    jira_ticket = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    false_positive = models.TextField(null=True, blank=True)


class task_schedule_db(models.Model):
    task_id = models.TextField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)
    schedule_time = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scanner = models.TextField(blank=True, null=True)
    periodic_task = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)