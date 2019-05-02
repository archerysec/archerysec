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


class NetworkScanSerializer(serializers.Serializer):
    scan_ip = serializers.IPAddressField(required=True,
                                         help_text="Network IP should be provided")
    project_id = serializers.UUIDField(required=True,
                                       help_text="Project ID should be provided")
    target_id = serializers.UUIDField(read_only=True)
    scan_id = serializers.UUIDField(read_only=True)
    scan_status = serializers.CharField(read_only=True)
    total_vul = serializers.CharField(read_only=True)
    high_total = serializers.CharField(read_only=True)
    medium_total = serializers.CharField(read_only=True)
    low_total = serializers.CharField(read_only=True)
    date_created = serializers.DateTimeField(read_only=True)
    date_modified = serializers.DateTimeField(read_only=True)


class NetworkScanResultSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True,
                                    help_text="Provide ScanId")
    vul_id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    owner = serializers.CharField(read_only=True)
    comment = serializers.CharField(read_only=True)
    creation_time = serializers.CharField(read_only=True)
    modification_time = serializers.CharField(read_only=True)
    user_tags = serializers.CharField(read_only=True)
    host = serializers.CharField(read_only=True)
    port = serializers.CharField(read_only=True)
    nvt = serializers.CharField(read_only=True)
    scan_nvt_version = serializers.CharField(read_only=True)
    threat = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    qod = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    term = serializers.CharField(read_only=True)
    keywords = serializers.CharField(read_only=True)
    field = serializers.CharField(read_only=True)
    filtered = serializers.CharField(read_only=True)
    page = serializers.CharField(read_only=True)
    vuln_color = serializers.CharField(read_only=True)
    family = serializers.CharField(read_only=True)
    cvss_base = serializers.CharField(read_only=True)
    cve = serializers.CharField(read_only=True)
    bid = serializers.CharField(read_only=True)
    xref = serializers.CharField(read_only=True)
    tags = serializers.CharField(read_only=True)
    banner = serializers.CharField(read_only=True)
    date_time = serializers.CharField(read_only=True)