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


class CicdDb(models.Model):
    class Meta:
        db_table = "cicddb"
        verbose_name_plural = "CI/CD"

    cicd_id = models.UUIDField(blank=True)
    name = models.TextField(blank=True)
    description = models.TextField(blank=True)
    project = models.ForeignKey(
        "projects.ProjectDb", on_delete=models.CASCADE, null=True
    )
    threshold = models.TextField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)
    threshold_count = models.IntegerField(blank=True, null=True)
    build_id = models.TextField(blank=True, null=True)
    commit_hash = models.TextField(blank=True, null=True)
    branch_tag = models.TextField(blank=True, null=True)
    repo = models.URLField(blank=True, null=True)
    scm_server = models.TextField(blank=True, null=True)
    build_server = models.TextField(blank=True, null=True)
    target_name = models.TextField(blank=True, null=True)
    target = models.TextField(blank=True, null=True)
    scanner = models.TextField(blank=True, null=True)
    command = models.TextField(blank=True, null=True)
    total_vul = models.IntegerField(blank=True, null=True)
    critical_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    info_vul = models.IntegerField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cicd_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cicd_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class ScannerCommand(models.Model):
    scanner = models.CharField(max_length=50, blank=True)
    command = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="scanner_command_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="scanner_command_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)
