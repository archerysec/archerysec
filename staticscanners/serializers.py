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


class StaticScanDbSerializer(serializers.Serializer):
    project_name = serializers.CharField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.CharField(read_only=True)
    scan_date = serializers.CharField(read_only=True)
    scan_status = serializers.CharField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    critical_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    info_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.CharField(read_only=True)
    total_dup = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True)
    scanner = serializers.CharField(read_only=True)


class StaticScanResultsDbSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.CharField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    vuln_id = serializers.UUIDField(read_only=True)
    false_positive = serializers.CharField(read_only=True)
    severity_color = serializers.CharField(read_only=True)
    dup_hash = serializers.CharField(read_only=True)
    vuln_duplicate = serializers.CharField(read_only=True)
    false_positive_hash = serializers.CharField(read_only=True)
    vuln_status = serializers.CharField(read_only=True)
    jira_ticket = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    references = serializers.CharField(read_only=True)
    fileName = serializers.CharField(read_only=True)
    filePath = serializers.CharField(read_only=True)
    solution = serializers.CharField(read_only=True)
    scanner = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True)
