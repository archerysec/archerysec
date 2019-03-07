# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


class inspec_scans_db(models.Model):
    scan_url = models.URLField(blank=True)
    scan_id = models.TextField(blank=True)
    code_desc = models.TextField(blank=True)
    status = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    info_vul = models.IntegerField(blank=True, null=True)
    project_id = models.UUIDField(null=True)
    date_time = models.DateTimeField(null=True)
    total_dup = models.TextField(blank=True, null=True)