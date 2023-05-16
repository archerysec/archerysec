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
from django.utils import timezone

from user_management.models import Organization, UserProfile


class jirasetting(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    jira_server = models.TextField(blank=True, null=True)
    jira_username = models.TextField(blank=True, null=True)
    jira_password = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="jira_ticket_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        related_name="jira_ticket_db_updated",
        on_delete=models.SET_NULL,
        null=True,
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)
