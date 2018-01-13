# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# Create your models here.
class project_db(models.Model):
    project_id = models.TextField(blank=True)
    project_name = models.TextField(blank=True)
    project_start = models.TextField(blank=True)
    project_end = models.TextField(blank=True)
    project_owner = models.TextField(blank=True)
    project_disc = models.TextField(blank=True)
    project_status = models.TextField(blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)


class project_scan_db(models.Model):
    project_url = models.TextField(blank=True) #this is scan url
    project_ip = models.TextField(blank=True)
    scan_type = models.TextField(blank=True)
    project_id = models.TextField(blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
