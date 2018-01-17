# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class APIScan_db(models.Model):
    project_id = models.UUIDField(blank=True)
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    req_header = models.TextField(blank=True)
    req_body = models.TextField(blank=True)
    method = models.CharField(blank=True, max_length=20)
    auth_url = models.CharField(blank=True, max_length=10)
    auth_token_key = models.TextField(blank=True)


class api_token_db(models.Model):
    project_id = models.UUIDField(blank=True)
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    api_token = models.TextField(blank=True)