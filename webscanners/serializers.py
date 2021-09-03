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


class WebScansDbSerializer(serializers.Serializer):
    scan_url = serializers.URLField(read_only=True)
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
    scanner = serializers.CharField(read_only=True)


class WebScanResultsDbSerializer(serializers.Serializer):
    vuln_id = serializers.UUIDField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.CharField(read_only=True)
    url = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    solution = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    instance = serializers.CharField(read_only=True)
    reference = serializers.CharField(read_only=True)
    project_id = serializers.CharField(read_only=True)
    severity_color = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    false_positive = serializers.CharField(read_only=True)
    jira_ticket = serializers.CharField(read_only=True)
    vuln_status = serializers.CharField(read_only=True)
    dup_hash = serializers.CharField(read_only=True)
    vuln_duplicate = serializers.CharField(read_only=True)
    false_positive_hash = serializers.CharField(read_only=True)
    scanner = serializers.CharField(read_only=True)


class UploadScanSerializer(serializers.Serializer):
    project_id = serializers.UUIDField()
    scanner = serializers.CharField()
    xml_file = serializers.FileField()
    scan_url = serializers.URLField()


class WebScanStatusSerializer(serializers.Serializer):
    scan_url = serializers.URLField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    vul_num = serializers.CharField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    total_vul = serializers.CharField(read_only=True)
    high_vul = serializers.CharField(read_only=True)
    medium_vul = serializers.CharField(read_only=True)
    low_vul = serializers.CharField(read_only=True)
    date_created = serializers.DateTimeField(read_only=True)
    date_modified = serializers.DateTimeField(read_only=True)
    rescan_id = serializers.CharField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.CharField(read_only=True)
    total_dup = serializers.CharField(read_only=True)


class ZapScanStatusDataSerializers(serializers.Serializer):

    scan_id = serializers.UUIDField(read_only=True)
    scan_status = serializers.CharField(required=True)
