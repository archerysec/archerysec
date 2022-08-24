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

import uuid

from django.conf import settings
from django.db import models
from django.db.models import F, Func, Sum

from user_management.models import UserProfile


class ProjectDb(models.Model):
    """ Class for Project model """

    class Meta:
        db_table = "project"
        verbose_name_plural = "Projects"

    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    project_name = models.CharField(max_length=255)
    project_start = models.TextField(blank=True)
    project_end = models.TextField(blank=True)
    project_owner = models.TextField(blank=True)
    project_disc = models.TextField(blank=True)
    project_status = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    total_vuln = models.IntegerField(blank=True, null=True)
    total_critical = models.IntegerField(blank=True, null=True)
    total_high = models.IntegerField(blank=True, null=True)
    total_medium = models.IntegerField(blank=True, null=True)
    total_low = models.IntegerField(blank=True, null=True)
    total_open = models.IntegerField(blank=True, null=True)
    total_false = models.IntegerField(blank=True, null=True)
    total_close = models.IntegerField(blank=True, null=True)
    total_net = models.IntegerField(blank=True, null=True)
    total_web = models.IntegerField(blank=True, null=True)
    total_static = models.IntegerField(blank=True, null=True)
    critical_net = models.IntegerField(blank=True, null=True)
    critical_web = models.IntegerField(blank=True, null=True)
    critical_static = models.IntegerField(blank=True, null=True)
    high_net = models.IntegerField(blank=True, null=True)
    high_web = models.IntegerField(blank=True, null=True)
    high_static = models.IntegerField(blank=True, null=True)
    medium_net = models.IntegerField(blank=True, null=True)
    medium_web = models.IntegerField(blank=True, null=True)
    medium_static = models.IntegerField(blank=True, null=True)
    low_net = models.IntegerField(blank=True, null=True)
    low_web = models.IntegerField(blank=True, null=True)
    low_static = models.IntegerField(blank=True, null=True)

    created_time = models.DateTimeField(auto_now_add=True, blank=True)
    created_by = models.ForeignKey(
        UserProfile,
        related_name="project_creator",
        on_delete=models.SET_NULL,
        null=True,
    )
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)
    updated_by = models.ForeignKey(
        UserProfile, related_name="project_editor", on_delete=models.SET_NULL, null=True
    )
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.project_name


class ProjectScanDb(models.Model):
    class Meta:
        db_table = "projectscandb"
        verbose_name_plural = "Project Scans Db"

    project_url = models.TextField(blank=True)  # this is scan url
    project_ip = models.TextField(blank=True)
    scan_type = models.TextField(blank=True)
    project = models.ForeignKey(
        "projects.ProjectDb", on_delete=models.CASCADE, null=True
    )
    date_time = models.DateTimeField(null=True)
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)


class Month(Func):
    function = "EXTRACT"
    template = "%(function)s(MONTH from %(expressions)s)"
    output_field = models.IntegerField()


class MonthSqlite(Func):
    function = "STRFTIME"
    template = '%(function)s("%%m", %(expressions)s)'
    output_field = models.CharField()


class MonthDb(models.Model):
    class Meta:
        db_table = "monthdb"
        verbose_name_plural = "Month Db"

    month = models.TextField(blank=True, null=True)
    critical = models.IntegerField(blank=True, null=True, default=0)
    high = models.IntegerField(blank=True, default=0)
    medium = models.IntegerField(blank=True, default=0)
    low = models.IntegerField(blank=True, default=0)
    project = models.ForeignKey(
        "projects.ProjectDb", on_delete=models.CASCADE, null=True
    )
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)
