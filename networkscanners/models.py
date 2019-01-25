# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

from django.db import models
from fernet_fields import EncryptedTextField


class ov_scan_result_db(models.Model):
    scan_id = models.TextField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    project_id = models.UUIDField(null=True)
    vul_id = models.TextField(blank=True)
    name = models.TextField(blank=True)
    owner = models.TextField(blank=True)
    comment = models.TextField(blank=True)
    creation_time = models.TextField(blank=True)
    modification_time = models.TextField(blank=True)
    user_tags = models.TextField(blank=True)
    host = models.TextField(blank=True)
    port = models.TextField(blank=True)
    nvt = models.TextField(blank=True)
    scan_nvt_version = models.TextField(blank=True)
    threat = models.TextField(blank=True)
    severity = models.TextField(blank=True)
    qod = models.TextField(blank=True)
    description = models.TextField(blank=True)
    term = models.TextField(blank=True)
    keywords = models.TextField(blank=True)
    field = models.TextField(blank=True)
    filtered = models.TextField(blank=True)
    page = models.TextField(blank=True)
    vuln_color = models.TextField(blank=True)
    family = models.TextField(blank=True)
    cvss_base = models.TextField(blank=True)
    cve = models.TextField(blank=True)
    bid = models.TextField(blank=True)
    xref = models.TextField(blank=True)
    tags = models.TextField(blank=True)
    banner = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    false_positive = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    scanner = models.TextField( default='OpenVAS', editable=False)


class scan_save_db(models.Model):
    scan_id = models.TextField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True)
    target_id = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_total = models.IntegerField(blank=True, null=True)
    medium_total = models.IntegerField(blank=True, null=True)
    low_total = models.IntegerField(blank=True, null=True)
    project_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    total_dup = models.IntegerField(blank=True, null=True)


class task_schedule_db(models.Model):
    task_id = models.TextField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)
    schedule_time = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scanner = models.TextField(blank=True, null=True)
    periodic_task = models.TextField(blank=True, null=True)


class nessus_report_db(models.Model):
    project_id = models.UUIDField(null=True)
    scan_id = models.TextField(blank=True)
    vul_id = models.TextField(blank=True)
    agent = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    fname = models.TextField(blank=True, null=True)
    plugin_modification_date = models.TextField(blank=True, null=True)
    plugin_name = models.TextField(blank=True, null=True)
    plugin_publication_date = models.TextField(blank=True, null=True)
    plugin_type = models.TextField(blank=True, null=True)
    risk_factor = models.TextField(blank=True, null=True)
    script_version = models.TextField(blank=True, null=True)
    see_also = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    synopsis = models.TextField(blank=True, null=True)
    plugin_output = models.TextField(blank=True, null=True)
    false_positive = models.TextField(blank=True, null=True)
    pluginName = models.TextField(blank=True, null=True)
    pluginID = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    svc_name = models.TextField(blank=True, null=True)
    pluginFamily = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True, null=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    scanner = models.TextField( default='Nessus', editable=False)


class nessus_scan_db(models.Model):
    scan_id = models.TextField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True)
    target_id = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    critical_total = models.IntegerField(blank=True, null=True)
    high_total = models.IntegerField(blank=True, null=True)
    medium_total = models.IntegerField(blank=True, null=True)
    low_total = models.IntegerField(blank=True, null=True)
    project_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    total_dup = models.IntegerField(blank=True, null=True)
