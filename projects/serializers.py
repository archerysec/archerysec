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

from rest_framework import serializers


class ProjectDataSerializers(serializers.Serializer):

    project_id = serializers.UUIDField(read_only=True)
    project_name = serializers.CharField(required=True, help_text="Project Name")
    project_disc = serializers.CharField(required=True, help_text="Project Description")
    project_start = serializers.DateField(
        required=False, help_text="Project start date"
    )
    project_end = serializers.DateField(required=False, help_text="Project End date")
    project_owner = serializers.CharField(required=False, help_text="Project Owner")
    project_status = serializers.CharField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    total_high = serializers.IntegerField(read_only=True)
    total_medium = serializers.IntegerField(read_only=True)
    total_low = serializers.IntegerField(read_only=True)
    total_open = serializers.IntegerField(read_only=True)
    total_false = serializers.IntegerField(read_only=True)
    total_close = serializers.IntegerField(read_only=True)
    total_net = serializers.IntegerField(read_only=True)
    total_web = serializers.IntegerField(read_only=True)
    total_static = serializers.IntegerField(read_only=True)
    high_net = serializers.IntegerField(read_only=True)
    high_web = serializers.IntegerField(read_only=True)
    high_static = serializers.IntegerField(read_only=True)
    medium_net = serializers.IntegerField(read_only=True)
    medium_web = serializers.IntegerField(read_only=True)
    medium_static = serializers.IntegerField(read_only=True)
    low_net = serializers.IntegerField(read_only=True)
    low_web = serializers.IntegerField(read_only=True)
    low_static = serializers.IntegerField(read_only=True)


class ProjectCreateSerializers(serializers.Serializer):
    project_name = serializers.CharField(required=True, help_text="Project Name")
    project_disc = serializers.CharField(required=True, help_text="Project Description")