# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


# SSLScan Model.
class sslscan_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    sslscan_output = models.TextField(blank=True, null=True)


# Nikto Models
class nikto_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    nikto_scan_output = models.TextField(blank=True, null=True)
    date_time = models.TextField(null=True, blank=True)


class nikto_vuln_db(models.Model):
    vuln_id = models.UUIDField(blank=True, null=True)
    scan_id = models.UUIDField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_url = models.TextField(blank=True, null=True)
    discription = models.TextField(blank=True, null=True)
    targetip = models.TextField(blank=True, null=True)
    hostname = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    uri = models.TextField(blank=True, null=True)
    httpmethod = models.TextField(blank=True, null=True)
    testlinks = models.TextField(blank=True, null=True)
    osvdb = models.TextField(blank=True, null=True)
    false_positive = models.TextField(null=True, blank=True)
    jira_ticket = models.TextField(null=True, blank=True)
    vuln_status = models.TextField(null=True, blank=True)
    dup_hash = models.TextField(null=True, blank=True)
    vuln_duplicate = models.TextField(null=True, blank=True)
    false_positive_hash = models.TextField(null=True, blank=True)
    date_time = models.TextField(null=True, blank=True)



# Nmap tool models
class nmap_scan_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    scan_ip = models.TextField(blank=True, null=True)
    total_ports = models.TextField(blank=True, null=True)
    total_open_ports = models.TextField(blank=True, null=True)
    total_close_ports = models.TextField(blank=True, null=True)


class nmap_result_db(models.Model):
    scan_id = models.TextField(blank=True, null=True)
    project_id = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    protocol = models.TextField(blank=True, null=True)
    port = models.TextField(blank=True, null=True)
    state = models.TextField(blank=True, null=True)
    reason = models.TextField(blank=True, null=True)
    reason_ttl = models.TextField(blank=True, null=True)
    version = models.TextField(blank=True, null=True)
    extrainfo = models.TextField(blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    conf = models.TextField(blank=True, null=True)
    method = models.TextField(blank=True, null=True)
    type_p = models.TextField(blank=True, null=True)
    osfamily = models.TextField(blank=True, null=True)
    vendor = models.TextField(blank=True, null=True)
    osgen = models.TextField(blank=True, null=True)
    accuracy = models.TextField(blank=True, null=True)
    cpe = models.TextField(blank=True, null=True)
    used_state = models.TextField(blank=True, null=True)
    used_portid = models.TextField(blank=True, null=True)
    used_proto = models.TextField(blank=True, null=True)

# NOTE[gmedian]: just base on the previous existing table in order not to make anything non-working
class nmap_vulners_port_result_db(nmap_result_db):
    vulners_extrainfo = models.TextField(blank=True, null=True)
