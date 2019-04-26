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


class inspec_scan_db(models.Model):
    scan_id = models.UUIDField(blank=True, null=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True, null=True)
    project_id = models.UUIDField(blank=True, null=True)
    project_name = models.TextField(blank=True, null=True)
    total_vuln = models.IntegerField(blank=True, null=True)
    scan_status = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)
    total_dup = models.IntegerField(blank=True, null=True)
    SEVERITY_HIGH = models.IntegerField(blank=True, null=True)
    SEVERITY_MEDIUM = models.IntegerField(blank=True, null=True)
    SEVERITY_LOW = models.IntegerField(blank=True, null=True)
    inspec_failed = models.IntegerField(blank=True, null=True)
    inspec_passed = models.IntegerField(blank=True, null=True)
    inspec_skipped = models.IntegerField(blank=True, null=True)


class inspec_scan_results_db(models.Model):
    scan_id = models.UUIDField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    vuln_id = models.UUIDField(blank=True)
    false_positive = models.TextField(null=True, blank=True)
    vul_col = models.TextField(blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)

    Name = models.TextField(null=True, blank=True)
    platform_name = models.TextField(null=True, blank=True)
    platform_release = models.TextField(null=True, blank=True)
    profiles_name = models.TextField(null=True, blank=True)
    profiles_sha256 = models.TextField(null=True, blank=True)
    profiles_title = models.TextField(null=True, blank=True)
    profiles_supports = models.TextField(null=True, blank=True)
    attributes_name = models.TextField(null=True, blank=True)
    attributes_options_description = models.TextField(null=True, blank=True)
    attributes_options_default = models.TextField(null=True, blank=True)
    groups_id = models.TextField(null=True, blank=True)
    groups_controls = models.TextField(null=True, blank=True)
    controls_id = models.TextField(null=True, blank=True)
    controls_title = models.TextField(null=True, blank=True)
    controls_desc = models.TextField(null=True, blank=True)
    controls_descriptions = models.TextField(null=True, blank=True)
    controls_impact = models.TextField(null=True, blank=True)
    controls_refs = models.TextField(null=True, blank=True)
    controls_tags_severity = models.TextField(null=True, blank=True)
    controls_tags_cis_id = models.TextField(null=True, blank=True)
    controls_tags_cis_control = models.TextField(null=True, blank=True)
    controls_tags_cis_level = models.TextField(null=True, blank=True)
    controls_tags_audit = models.TextField(null=True, blank=True)
    controls_tags_fix = models.TextField(null=True, blank=True)
    controls_tags_defaultvalue = models.TextField(null=True, blank=True)
    controls_code = models.TextField(null=True, blank=True)
    controls_source_location = models.TextField(null=True, blank=True)
    controls_results_status = models.TextField(null=True, blank=True)
    controls_results_code_desc = models.TextField(null=True, blank=True)
    controls_results_run_time = models.TextField(null=True, blank=True)
    controls_results_start_time = models.TextField(null=True, blank=True)
    controls_results_message = models.TextField(null=True, blank=True)
    controls_results_backtrace = models.TextField(null=True, blank=True)
    controls_tags_audit_text = models.TextField(null=True, blank=True)

    scanner = models.TextField(default='inspec', editable=False)
