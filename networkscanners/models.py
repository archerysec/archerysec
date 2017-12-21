# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from fernet_fields import EncryptedTextField

class ov_scan_result_db(models.Model):
    scan_id = models.TextField(blank=True)
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

    family = models.TextField(blank=True)
    cvss_base = models.TextField(blank=True)
    cve = models.TextField(blank=True)
    bid = models.TextField(blank=True)
    xref = models.TextField(blank=True)
    tags = models.TextField(blank=True)
    banner = models.TextField(blank=True)


class scan_save_db(models.Model):
    scan_id = models.TextField(blank=True)
    scan_ip = models.TextField(blank=True)
    target_id = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    total_vul = models.TextField(blank=True)
    high_total = models.TextField(blank=True)
    medium_total = models.TextField(blank=True)
    low_total = models.TextField(blank=True)
