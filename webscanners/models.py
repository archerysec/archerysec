# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class zap_spider_db(models.Model):
    spider_url = models.TextField(blank=True)
    spider_scanid = models.TextField(blank=True)
    urls_num = models.TextField(blank=True)


class zap_scans_db(models.Model):
    scan_url = models.URLField(blank=True)
    scan_scanid = models.TextField(blank=True)
    vul_num = models.TextField(blank=True)
    vul_status = models.TextField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    project_id = models.UUIDField(null=True)
    date_time = models.DateTimeField(null=True)


class zap_spider_results(models.Model):
    spider_id = models.TextField(blank=True)
    spider_urls = models.TextField(blank=True)


class zap_scan_results_db(models.Model):
    vuln_id = models.TextField(blank=True)
    scan_id = models.TextField(blank=True)
    confidence = models.TextField(blank=True)
    wascid = models.TextField(blank=True)
    cweid = models.TextField(blank=True)
    risk = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    url = models.TextField(blank=True)
    name = models.TextField(blank=True)
    solution = models.TextField(blank=True)
    param = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    sourceid = models.TextField(blank=True)
    pluginId = models.TextField(blank=True)
    other = models.TextField(blank=True)
    attack = models.TextField(blank=True)
    messageId = models.TextField(blank=True)
    method = models.TextField(blank=True)
    alert = models.TextField(blank=True)
    ids = models.TextField(blank=True)
    description = models.TextField(blank=True)
    req_res = models.TextField(blank=True)
    project_id = models.TextField(blank=True)
    vuln_color = models.TextField(blank=True)

    note = models.TextField(blank=True)
    rtt = models.TextField(blank=True)
    tags = models.TextField(blank=True)
    timestamp = models.TextField(blank=True)
    responseHeader = models.TextField(blank=True)
    requestBody = models.TextField(blank=True)
    responseBody = models.TextField(blank=True)
    requestHeader = models.TextField(blank=True)
    cookieParams = models.TextField(blank=True)
    res_type = models.TextField(blank=True)
    res_id = models.TextField(blank=True)
    date_time = models.DateTimeField(null=True)
    false_positive = models.TextField(null=True, blank=True)


class cookie_db(models.Model):
    url = models.TextField(blank=True)
    cookie = models.TextField(blank=True)


class excluded_db(models.Model):
    exclude_url = models.TextField(blank=True)


class burp_scan_db(models.Model):
    url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)


class burp_scan_result_db(models.Model):
    scan_id = models.UUIDField(blank=True)
    project_id = models.TextField(blank=True)
    vuln_id = models.UUIDField(blank=True)

    serialNumber = models.TextField(blank=True)
    types = models.TextField(blank=True)
    name = models.TextField(blank=True)
    host = models.TextField(blank=True)
    path = models.TextField(blank=True)
    location = models.TextField(blank=True)
    severity = models.TextField(blank=True)
    severity_color = models.TextField(blank=True)
    confidence = models.TextField(blank=True)
    issueBackground = models.TextField(blank=True)
    remediationBackground = models.TextField(blank=True)
    references = models.TextField(blank=True)
    vulnerabilityClassifications = models.TextField(blank=True)
    issueDetail = models.TextField(blank=True)
    requestresponse = models.TextField(blank=True)
    scan_request = models.TextField(blank=True)
    scan_response = models.TextField(blank=True)
    method = models.TextField(blank=True)
    false_positive = models.TextField(null=True, blank=True)


class web_scan_db(models.Model):
    scan_url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    total_vul = models.IntegerField(blank=True)
    high_vul = models.IntegerField(blank=True)
    medium_vul = models.IntegerField(blank=True)
    low_vul = models.IntegerField(blank=True)
    info_vuln = models.IntegerField(blank=True)
    scanner = models.TextField(blank=True)


class email_config_db(models.Model):
    email_id_from = models.EmailField(blank=True)
    email_subject = models.TextField(blank=True)
    email_message = models.TextField(blank=True)
    email_id_to = models.EmailField(blank=True)


class arachni_scan_db(models.Model):
    url = models.URLField(blank=True)
    scan_id = models.UUIDField(blank=True)
    scan_date = models.TextField(blank=True)
    scan_status = models.TextField(blank=True)
    project_id = models.UUIDField(blank=True)
    total_vul = models.IntegerField(blank=True, null=True)
    high_vul = models.IntegerField(blank=True, null=True)
    medium_vul = models.IntegerField(blank=True, null=True)
    low_vul = models.IntegerField(blank=True, null=True)
    date_time = models.DateTimeField(blank=True, null=True)


class arachni_scan_result_db(models.Model):
    scan_id = models.UUIDField(blank=True)
    project_id = models.TextField(blank=True)
    vuln_id = models.UUIDField(blank=True)

    name = models.TextField(blank=True)
    description = models.TextField(blank=True)
    remedy_guidance = models.TextField(blank=True)
    severity = models.TextField(blank=True)
    proof = models.TextField(blank=True)
    vuln_color = models.TextField(blank=True)
    url = models.TextField(blank=True)
    action = models.TextField(blank=True)
    body = models.TextField(blank=True)
    false_positive = models.TextField(blank=True)
    cwe = models.TextField(blank=True)
    ref_key = models.TextField(blank=True)
    ref_value = models.TextField(blank=True)
    vector_input_key = models.TextField(blank=True)
    vector_input_values = models.TextField(blank=True)
    vector_source_key = models.TextField(blank=True)
    vector_source_values = models.TextField(blank=True)
    page_body_data = models.TextField(blank=True)
    request_url = models.TextField(blank=True)
    request_method = models.TextField(blank=True)
    request_raw = models.TextField(blank=True)
    response_ip = models.TextField(blank=True)
    response_raw_headers = models.TextField(blank=True)
