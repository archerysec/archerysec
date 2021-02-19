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

from zapv2 import ZAPv2
from django.db.models import Q
import os
import time
import uuid
import json
import ast
from archerysettings.models import zap_settings_db, burp_setting_db, openvas_setting_db
import hashlib
try:
    from scanners.scanner_parser.web_scanner import zap_xml_parser
except Exception as e:
    print(e)
import defusedxml.ElementTree as ET
import platform
import subprocess
import sys
from datetime import datetime

# ZAP Database import

from webscanners.models import zap_scan_results_db, \
    zap_scans_db, \
    zap_spider_db, \
    cookie_db, \
    excluded_db

from archerysettings import load_settings

# Global Variables
setting_file = os.getcwd() + '/apidata.json'
# zap_setting = load_settings.ArcherySettings(setting_file, username=username)
zap_api_key = 'dwed23wdwedwwefw4rwrfw'
zap_hosts = '0.0.0.0'
zap_ports = '8090'

risk = ''
name = ''
attack = ''
confidence = ''
wascid = ''
description = ''
reference = ''
sourceid = ''
solution = ''
param = ''
method = ''
url = ''
pluginId = ''
other = ''
alert = ''
messageId = ''
evidence = ''
cweid = ''
risk = ''
vul_col = ''
all_vuln = ''


import socket
# Getting a random free tcp port in python using sockets

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port


def zap_local():
    random_port = str(get_free_tcp_port())
    zap_path = '/home/archerysec/app/zap/'
    executable = 'zap.sh'
    executable_path = os.path.join(zap_path, executable)

    zap_command = [executable_path, '-daemon', '-config', 'api.disablekey=false', '-config', 'api.key=' + zap_api_key,
                   '-port', random_port, '-host', zap_hosts, '-config', 'api.addrs.addr.name=.*', '-config',
                   'api.addrs.addr.regex=true']

    log_path = os.getcwd() + '/' + 'zap.log'

    with open(log_path, 'w+') as log_file:
        subprocess.Popen(zap_command, cwd=zap_path, stdout=log_file, stderr=subprocess.STDOUT)

    return random_port


def zap_connect(random_port, username):
    all_zap = zap_settings_db.objects.filter(username=username)

    zap_api_key = ''
    zap_hosts = '127.0.0.1'
    zap_ports = '8090'
    zap_enabled = False


    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        zap_api_key = 'dwed23wdwedwwefw4rwrfw'
        zap_hosts = '127.0.0.1'
        zap_ports = random_port

    if zap_enabled is True:
        for zap in all_zap:
            zap_api_key = zap.zap_api
            zap_hosts = zap.zap_url
            zap_ports = zap.zap_port
    zap = ZAPv2(apikey=zap_api_key,
                proxies={
                    'http': 'http://' + zap_hosts + ':' + str(zap_ports),
                    'https': 'https://' + zap_hosts + ':' + str(zap_ports)})
    return zap


def zap_replacer(target_url, random_port, username):
    zap = zap_connect(random_port=random_port, username=username)
    try:
        zap.replacer.remove_rule(description=target_url, apikey=zap_api_key)
    except Exception as e:
        print("ZAP Replacer error")

    return


def zap_spider_thread(count, random_port, username):
    zap = zap_connect(random_port=random_port, username=username)

    zap.spider.set_option_thread_count(count, apikey=zap_api_key)

    return


def zap_scan_thread(count, random_port, username):
    zap = zap_connect(random_port=random_port, username=username)

    zap.ascan.set_option_thread_per_host(count, apikey=zap_api_key)

    return


def zap_spider_setOptionMaxDepth(count, random_port, username):
    zap = zap_connect(random_port=random_port, username=username)

    zap.spider.set_option_max_depth(count, apikey=zap_api_key)

    return


def zap_scan_setOptionHostPerScan(count, random_port, username):
    zap = zap_connect(random_port=random_port, username=username)

    zap.ascan.set_option_host_per_scan(count, apikey=zap_api_key)

    return


class ZAPScanner:
    """
    ZAP Scanner Plugin. Interacting with ZAP Scanner API.
    """

    # Global variable's
    spider_alert = []
    target_url = []
    driver = []
    new_uri = []
    excluded_url = []
    vul_col = []
    note = []
    rtt = []
    tags = []
    timestamp = []
    responseHeader = []
    requestBody = []
    responseBody = []
    requestHeader = []
    cookieParams = []
    res_type = []
    res_id = []
    alert = []
    project_id = None
    scan_ip = None
    burp_status = 0
    serialNumber = []
    types = []
    name = []
    host = []
    path = []
    location = []
    severity = []
    confidence = []
    issueBackground = []
    remediationBackground = []
    references = []
    vulnerabilityClassifications = []
    issueDetail = []
    requestresponse = []
    vuln_id = []
    methods = []
    dec_res = []
    dec_req = []
    decd_req = []
    scanner = []
    all_scan_url = []
    all_url_vuln = []
    false_positive = ''

    """ Connect with ZAP scanner global variable """

    def __init__(self, target_url, project_id, rescan_id, rescan, random_port, username):
        """

        :param target_url: Target URL parameter.
        :param project_id: Project ID parameter.
        """
        self.target_url = target_url
        self.project_id = project_id
        self.rescan_id = rescan_id
        self.rescan = rescan
        self.username = username
        self.zap = zap_connect(random_port=random_port, username=username)

    def exclude_url(self):
        """
        Exclude URL from scan. Data are fetching from Archery database.
        :return:
        """
        excluded_url = ""
        try:
            all_excluded = excluded_db.objects.filter(
                Q(
                    exclude_url__icontains=self.target_url
                )
            )
            for data in all_excluded:
                excluded_url = data.exclude_url
                print("excluded url ", excluded_url)
        except Exception as e:
            print(e)

        try:
            self.zap.spider.exclude_from_scan(
                regex=excluded_url,

            )
        except Exception as e:
            print(e)

        return excluded_url

    def cookies(self):
        """
        Cookies value extracting from Archery database and replacing
         into ZAP scanner.
        :return:
        """
        all_cookies = ""
        try:
            all_cookie = cookie_db.objects.filter(
                Q(
                    url__icontains=self.target_url
                )
            )
            for da in all_cookie:
                all_cookies = da.cookie

        except Exception as e:
            print(e)
        print("All cookies", all_cookies)
        print("Target URL---", self.target_url)

        try:
            self.zap.replacer.add_rule(
                apikey=zap_api_key,
                description=self.target_url,
                enabled="true",
                matchtype='REQ_HEADER',
                matchregex="false",
                replacement=all_cookies,
                matchstring="Cookie",
                initiators=""
            )
        except Exception as e:
            print(e)

    def zap_spider(self):
        """
        Scan trigger in ZAP Scanner and return Scan ID
        :return:
        """
        spider_id = ""

        try:
            print("targets:-----", self.target_url)
            try:
                spider_id = self.zap.spider.scan(self.target_url)
            except Exception as e:
                print("Spider Error")
            time.sleep(5)

            save_all = zap_spider_db(
                spider_url=self.target_url,
                spider_scanid=spider_id
            )
            save_all.save()
        except Exception as e:
            print(e)

        return spider_id

    def zap_spider_thread(self, thread_value):
        """
        The function use for the increasing Spider thread in ZAP scanner.
        :return:
        """
        thread = ""
        try:
            thread = self.zap.spider.set_option_thread_count(
                apikey=zap_api_key,
                integer=thread_value
            )

        except Exception as e:
            print("Spider Thread error")

        return thread

    def spider_status(self, spider_id):
        """
        The function return the spider status.
        :param spider_id:
        :return:
        """

        try:
            while int(self.zap.spider.status(spider_id)) < 100:
                global spider_status
                spider_status = self.zap.spider.status(spider_id)

                time.sleep(5)
        except Exception as e:
            print(e)

        spider_status = "100"
        return spider_status

    def spider_result(self, spider_id):
        """
        The function return spider result.
        :param spider_id:
        :return:
        """
        data_out = ""
        try:
            spider_res_out = self.zap.spider.results(spider_id)
            data_out = ("\n".join(map(str, spider_res_out)))
        except Exception as e:
            print(e)

        return data_out

    def zap_scan(self):
        """
        The function Trigger scan in ZAP scanner
        :return:
        """
        scan_id = ""

        try:
            scan_id = self.zap.ascan.scan(self.target_url)
        except Exception as e:
            print("ZAP SCAN ERROR")

        return scan_id

    def zap_scan_status(self, scan_id, un_scanid):
        """
        The function return the ZAP Scan Status.
        :param scan_id:
        :return:
        """

        try:
            while int(self.zap.ascan.status(scan_id)) < 100:
                scan_status = self.zap.ascan.status(scan_id)
                print("ZAP Scan Status:", scan_status)
                time.sleep(10)
                zap_scans_db.objects.filter(
                    scan_scanid=un_scanid
                ).update(vul_status=scan_status)
        except Exception as e:
            print(e)

        scan_status = 100
        zap_scans_db.objects.filter(
            scan_scanid=un_scanid
        ).update(
            vul_status=scan_status
        )
        return scan_status

    def zap_scan_result(self, target_url, username):
        """
        The function return ZAP Scan Results.
        :return:
        """
        global all_vuln
        zap_enabled = False

        all_zap = zap_settings_db.objects.filter(username=username)
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            try:
                all_vuln = self.zap.core.xmlreport()
                print(target_url)

            except Exception as e:
                print("zap scan result error")
        else:
            all_vuln = self.zap.core.alerts(baseurl=target_url)

        return all_vuln

    def zap_result_save(self, all_vuln, project_id, un_scanid, username, target_url):
        """
        The function save all data in Archery Database
        :param all_vuln:
        :param project_id:
        :param un_scanid:
        :return:
        """
        date_time = datetime.now()
        zap_enabled = False

        all_zap = zap_settings_db.objects.filter(username=username)
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            root_xml = ET.fromstring(all_vuln)
            en_root_xml = ET.tostring(root_xml, encoding='utf8').decode('ascii', 'ignore')
            root_xml_en = ET.fromstring(en_root_xml)
            try:
                zap_xml_parser.xml_parser(username=username,
                                          project_id=project_id,
                                          scan_id=un_scanid,
                                          root=root_xml_en)
                self.zap.core.delete_all_alerts()
            except Exception as e:
                print(e)
        else:
            global name, attack, wascid, description, reference, \
                reference, sourceid, \
                solution, \
                param, \
                method, url, messageId, alert, pluginId, other, evidence, cweid, risk, vul_col, false_positive
            for data in all_vuln:
                for key, value in data.items():
                    if key == 'name':
                        name = value

                    if key == 'attack':
                        attack = value

                    if key == 'wascid':
                        wascid = value

                    if key == 'description':
                        description = value

                    if key == 'reference':
                        reference = value

                    if key == 'sourceid':
                        sourceid = value

                    if key == 'solution':
                        solution = value

                    if key == 'param':
                        param = value

                    if key == 'method':
                        method = value

                    if key == 'url':
                        url = value

                    if key == 'pluginId':
                        pluginId = value

                    if key == 'other':
                        other = value

                    if key == 'alert':
                        alert = value

                    if key == 'attack':
                        attack = value

                    if key == 'messageId':
                        messageId = value

                    if key == 'evidence':
                        evidence = value

                    if key == 'cweid':
                        cweid = value

                    if key == 'risk':
                        risk = value
                if risk == "High":
                    vul_col = "danger"
                    risk = "High"
                elif risk == 'Medium':
                    vul_col = "warning"
                    risk = "Medium"
                elif risk == 'info':
                    vul_col = "info"
                    risk = "Low"
                else:
                    vul_col = "info"
                    risk = "Low"

                dup_data = name + risk + target_url
                duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                match_dup = zap_scan_results_db.objects.filter(
                    dup_hash=duplicate_hash).values('dup_hash').distinct()
                lenth_match = len(match_dup)

                vuln_id = uuid.uuid4()
                if lenth_match == 0:
                    duplicate_vuln = 'No'
                    dump_data = zap_scan_results_db(vuln_id=vuln_id,
                                                    vuln_color=vul_col,
                                                    scan_id=un_scanid,
                                                    project_id=project_id,
                                                    confidence=confidence,
                                                    wascid=wascid,
                                                    risk=risk,
                                                    reference=reference,
                                                    url=url,
                                                    name=name,
                                                    solution=solution,
                                                    param=url,
                                                    sourceid=sourceid,
                                                    pluginId=pluginId,
                                                    alert=alert,
                                                    description=description,
                                                    false_positive='No',
                                                    rescan='No',
                                                    vuln_status='Open',
                                                    dup_hash=duplicate_hash,
                                                    vuln_duplicate=duplicate_vuln,
                                                    evidence=evidence,
                                                    username=username
                                                    )
                    dump_data.save()
                else:
                    duplicate_vuln = 'Yes'

                    dump_data = zap_scan_results_db(vuln_id=vuln_id,
                                                    vuln_color=vul_col,
                                                    scan_id=un_scanid,
                                                    project_id=project_id,
                                                    confidence=confidence,
                                                    wascid=wascid,
                                                    risk=risk,
                                                    reference=reference,
                                                    url=url,
                                                    name=name,
                                                    solution=solution,
                                                    param=url,
                                                    sourceid=sourceid,
                                                    pluginId=pluginId,
                                                    alert=alert,
                                                    description=description,
                                                    false_positive='Duplicate',
                                                    rescan='No',
                                                    vuln_status='Duplicate',
                                                    dup_hash=duplicate_hash,
                                                    vuln_duplicate=duplicate_vuln,
                                                    evidence=evidence,
                                                    username=username
                                                    )
                    dump_data.save()

                false_p = zap_scan_results_db.objects.filter(
                    false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                vul_dat = zap_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
                full_data = []
                for data in vul_dat:
                    key = 'Evidence'
                    value = data.evidence
                    instance = key + ': ' + value
                    full_data.append(instance)
                removed_list_data = ','.join(full_data)
                zap_scan_results_db.objects.filter(username=username, vuln_id=vuln_id).update(param=full_data)

            zap_all_vul = zap_scan_results_db.objects.filter(username=username, scan_id=un_scanid, false_positive='No')

            duplicate_count = zap_scan_results_db.objects.filter(username=username, scan_id=un_scanid,
                                                                 vuln_duplicate='Yes')

            total_high = len(zap_all_vul.filter(risk="High"))
            total_medium = len(zap_all_vul.filter(risk="Medium"))
            total_low = len(zap_all_vul.filter(risk="Low"))
            total_info = len(zap_all_vul.filter(risk="Informational"))
            total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))
            total_vul = total_high + total_medium + total_low + total_info

            zap_scans_db.objects.filter(username=username, scan_scanid=un_scanid) \
                .update(total_vul=total_vul,
                        date_time=date_time,
                        high_vul=total_high,
                        medium_vul=total_medium,
                        low_vul=total_low,
                        info_vul=total_info,
                        total_dup=total_duplicate,
                        scan_url=target_url
                        )
            if total_vul == total_duplicate:
                zap_scans_db.objects.filter(username=username, scan_scanid=un_scanid) \
                    .update(total_vul=total_vul,
                            date_time=date_time,
                            high_vul=total_high,
                            medium_vul=total_medium,
                            low_vul=total_low,
                            total_dup=total_duplicate
                            )


    def zap_shutdown(self):
        """

        :return:
        """
        self.zap.core.shutdown(apikey=zap_api_key)
