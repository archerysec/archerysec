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


class zap_spider_db(models.Model):
    spider_url = models.TextField(blank=True)
    spider_scanid = models.TextField(blank=True)
    urls_num = models.TextField(blank=True)
    username = models.CharField(max_length=256, null=True)


class WebScansDb(models.Model):
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
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


class WebScanResultsDb(models.Model):
    vuln_id = models.UUIDField(blank=True)
    scan_id = models.UUIDField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    url = models.TextField(blank=True)
    title = models.TextField(blank=True)
    solution = models.TextField(blank=True)
    description = models.TextField(blank=True)
    instance = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    project_id = models.TextField(blank=True)
    severity_color = models.TextField(blank=True)
    severity = models.TextField(blank=True, null=True)
    date_time = models.DateTimeField(null=True)
    false_positive = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    scanner = models.TextField(editable=False)
    username = models.CharField(max_length=256, null=True)


class cookie_db(models.Model):
    url = models.TextField(blank=True)
    cookie = models.TextField(blank=True)
    username = models.CharField(max_length=256, null=True)


class excluded_db(models.Model):
    exclude_url = models.TextField(blank=True)
    username = models.CharField(max_length=256, null=True)


class web_scan_db(models.Model):
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    total_vul = models.IntegerField(blank=True)
    high_vul = models.IntegerField(blank=True)
    medium_vul = models.IntegerField(blank=True)
    low_vul = models.IntegerField(blank=True)
    info_vuln = models.IntegerField(blank=True)
    scanner = models.TextField(blank=True)
    username = models.CharField(max_length=256, null=True)


class email_config_db(models.Model):
    email_id_from = models.EmailField(blank=True)
    email_subject = models.TextField(blank=True)
    email_message = models.TextField(blank=True)
    email_id_to = models.EmailField(blank=True)
    username = models.CharField(max_length=256, null=True)


class task_schedule_db(models.Model):
    task_id = models.TextField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)
    schedule_time = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scanner = models.TextField(blank=True, null=True)
    periodic_task = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=256, null=True)