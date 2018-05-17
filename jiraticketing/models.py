# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class jirasetting(models.Model):
    jira_server = models.TextField(blank=True, null=True)
    jira_username = models.TextField(blank=True, null=True)
    jira_password = models.TextField(blank=True, null=True)
