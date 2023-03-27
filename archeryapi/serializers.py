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


class CreateUser(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)


class OrgAPIKeySerializer(serializers.Serializer):
    api_key = serializers.CharField(max_length=255)
    uu_id = serializers.CharField(max_length=255)


class GenericScanResultsDbSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
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
    solution = serializers.CharField(read_only=True)
    scanner = serializers.CharField(read_only=True)
    target = serializers.CharField(read_only=True)


class JiraLinkSerializer(serializers.Serializer):
    vuln_id = serializers.UUIDField(read_only=True)
    link_jira_ticket_id = serializers.CharField(max_length=255)
    current_jira_ticket_id = serializers.CharField(max_length=255)