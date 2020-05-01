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


class BanditScanStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class findbugsStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class DependencycheckStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class RetirejsStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class ClairStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class TrivyStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class NpmauditStatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)


class NodejsscanSatatusSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)
    project_name = serializers.CharField(read_only=True)
    total_vuln = serializers.IntegerField(read_only=True)
    SEVERITY_HIGH = serializers.IntegerField(read_only=True)
    SEVERITY_MEDIUM = serializers.IntegerField(read_only=True)
    SEVERITY_LOW = serializers.IntegerField(read_only=True)
