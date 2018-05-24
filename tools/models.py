# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class sslscan_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    sslscan_output = models.TextField(blank=True, null=True)