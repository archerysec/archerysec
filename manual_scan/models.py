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


class ManualScansDb(models.Model):
    scan_url = models.URLField(blank=True)
    scan_id = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    project = models.ForeignKey('projects.ProjectDb', on_delete=models.CASCADE, null=True)
    date_time = models.DateTimeField(null=True)
    pentest_type = models.TextField(blank=True, null=True)


class ManualScanResultsDb(models.Model):
    vuln_id = models.TextField(blank=True)
    scan_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    rescan_id = models.TextField(blank=True, null=True)
    vuln_name = models.TextField(blank=True, null=True)
    severity = models.TextField(blank=True, null=True)
    severity_color = models.TextField(blank=True, null=True)
    vuln_url = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True)
    description = models.TextField(blank=True, null=True)
    solution = models.TextField(blank=True, null=True)
    request_header = models.TextField(blank=True, null=True)
    response_header = models.TextField(blank=True, null=True)
    reference = models.TextField(blank=True, null=True)
    vuln_status = models.TextField(null=True, blank=True)
    project = models.ForeignKey('projects.ProjectDb', on_delete=models.CASCADE, null=True)
    Poc_Img = models.ImageField(null=True, blank=True)
    poc_description = models.TextField(null=True, blank=True)
    pentest_type = models.TextField(blank=True, null=True)


class VulnerabilityData(models.Model):
    vuln_data_id = models.TextField(blank=True)
    vuln_name = models.TextField(blank=True)
    vuln_description = models.TextField(blank=True)
    vuln_severity = models.TextField(blank=True)
    vuln_remediation = models.TextField(blank=True)
    vuln_references = models.TextField(blank=True)
    date_time = models.DateTimeField(blank=True, null=True)
