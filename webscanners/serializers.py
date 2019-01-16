#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from rest_framework import serializers
from .models import zap_scans_db


class WebScanSerializer(serializers.Serializer):
    scan_url = serializers.URLField(required=True, help_text=("Proper domain should be provided"))
    project_id = serializers.UUIDField(required=True, help_text=("Project ID should be provided"))
    scan_scanid = serializers.UUIDField(read_only=True)
    # vul_num = serializers.CharField(read_only=True)
    vul_status = serializers.IntegerField(read_only=True)
    total_vul = serializers.CharField(read_only=True)
    high_vul = serializers.CharField(read_only=True)
    medium_vul = serializers.CharField(read_only=True)
    low_vul = serializers.CharField(read_only=True)
    date_created = serializers.DateTimeField(read_only=True)
    date_modified = serializers.DateTimeField(read_only=True)


class WebScanResultSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    project_id = serializers.UUIDField(read_only=True)
    url = serializers.URLField(read_only=True)
    vuln_id = serializers.CharField(read_only=True)
    confidence = serializers.CharField(read_only=True)
    wascid = serializers.CharField(read_only=True)
    cweid = serializers.CharField(read_only=True)
    risk = serializers.CharField(read_only=True)
    reference = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)
    solution = serializers.CharField(read_only=True)
    param = serializers.CharField(read_only=True)
    evidence = serializers.CharField(read_only=True)
    sourceid = serializers.CharField(read_only=True)
    pluginId = serializers.CharField(read_only=True)
    other = serializers.CharField(read_only=True)
    attack = serializers.CharField(read_only=True)
    messageId = serializers.CharField(read_only=True)
    method = serializers.CharField(read_only=True)
    alert = serializers.CharField(read_only=True)
    ids = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    req_res = serializers.CharField(read_only=True)
    note = serializers.CharField(read_only=True)
    rtt = serializers.CharField(read_only=True)
    tags = serializers.CharField(read_only=True)
    timestamp = serializers.CharField(read_only=True)
    responseHeader = serializers.CharField(read_only=True)
    requestBody = serializers.CharField(read_only=True)
    responseBody = serializers.CharField(read_only=True)
    requestHeader = serializers.CharField(read_only=True)
    cookieParams = serializers.CharField(read_only=True)
    res_type = serializers.CharField(read_only=True)
    res_id = serializers.CharField(read_only=True)
    date_time = serializers.CharField(read_only=True)
    serialNumber = serializers.CharField(read_only=True)
    types = serializers.CharField(read_only=True)
    host = serializers.CharField(read_only=True)
    path = serializers.CharField(read_only=True)
    location = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    severity_color = serializers.CharField(read_only=True)
    issueBackground = serializers.CharField(read_only=True)
    remediationBackground = serializers.CharField(read_only=True)
    references = serializers.CharField(read_only=True)
    vulnerabilityClassifications = serializers.CharField(read_only=True)
    issueDetail = serializers.CharField(read_only=True)
    requestresponse = serializers.CharField(read_only=True)
    scan_request = serializers.CharField(read_only=True)
    scan_response = serializers.CharField(read_only=True)
    # method = serializers.CharField(read_only=True)
    false_positive = serializers.CharField(read_only=True)


class UploadScanSerializer(serializers.Serializer):
    project_id = serializers.UUIDField()
    scanner = serializers.CharField()
    xml_file = serializers.FileField()
    scan_url = serializers.URLField()


class WebScanStatusSerializer(serializers.Serializer):
    scan_url = serializers.URLField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    scan_scanid = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    vul_num = serializers.CharField(read_only=True)
    vul_status = serializers.IntegerField(read_only=True)
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


class ArachniScanStatusSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.CharField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)


class BurpScanStatusSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.CharField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)


class NetsparkerScanStatusSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    critical_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    info_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.CharField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)


class WebinspectScanStatusSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    critical_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    info_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.UUIDField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)


class AcunetixStatusSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    rescan_id = serializers.UUIDField(read_only=True)
    scan_date = serializers.DateTimeField(read_only=True)
    scan_status = serializers.IntegerField(read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    total_vul = serializers.IntegerField(read_only=True)
    critical_vul = serializers.IntegerField(read_only=True)
    high_vul = serializers.IntegerField(read_only=True)
    medium_vul = serializers.IntegerField(read_only=True)
    low_vul = serializers.IntegerField(read_only=True)
    info_vul = serializers.IntegerField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    rescan = serializers.UUIDField(read_only=True)
    total_dup = serializers.IntegerField(read_only=True)


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
