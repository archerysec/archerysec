# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class bandit_scan_db(models.Model):
    scan_id = models.UUIDField(blank=True, null=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True, null=True)
    project_id = models.UUIDField(blank=True, null=True)
    project_name = models.TextField(blank=True, null=True)
    source_line = models.TextField(blank=True, null=True)
    total_vuln = models.TextField(blank=True, null=True)
    SEVERITY_HIGH = models.TextField(blank=True, null=True)
    CONFIDENCE_HIGH = models.TextField(blank=True, null=True)
    CONFIDENCE_LOW = models.TextField(blank=True, null=True)
    SEVERITY_MEDIUM = models.TextField(blank=True, null=True)
    loc = models.IntegerField(blank=True, null=True)
    nosec = models.IntegerField(blank=True, null=True)
    CONFIDENCE_UNDEFINED = models.TextField(blank=True, null=True)
    SEVERITY_UNDEFINED = models.TextField(blank=True, null=True)
    CONFIDENCE_MEDIUM = models.TextField(blank=True, null=True)
    SEVERITY_LOW = models.TextField(blank=True, null=True)
    scan_status = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)


class bandit_scan_results_db(models.Model):
    scan_id = models.UUIDField(blank=True)
    rescan_id = models.TextField(blank=True, null=True)
    scan_date = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    vuln_id = models.UUIDField(blank=True)
    source_line = models.TextField(blank=True)
    line_number = models.TextField(blank=True)
    code = models.TextField(blank=True)
    issue_confidence = models.TextField(blank=True)
    false_positive = models.TextField(null=True, blank=True)
    line_range = models.TextField(blank=True)
    test_id = models.TextField(blank=True)
    issue_severity = models.TextField(blank=True)
    issue_text = models.TextField(blank=True)
    test_name = models.TextField(blank=True)
    filename = models.TextField(blank=True)
    more_info = models.TextField(blank=True)
    vul_col = models.TextField(blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
