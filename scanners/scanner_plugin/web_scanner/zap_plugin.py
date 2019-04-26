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
from scanners.scanner_parser.web_scanner import zap_xml_parser
import defusedxml.ElementTree as ET

# ZAP Database import

from webscanners.models import zap_scan_results_db, \
    zap_scans_db, \
    zap_spider_db, \
    cookie_db, \
    excluded_db

from archerysettings import load_settings

# Global Variables
setting_file = os.getcwd() + '/apidata.json'
zap_setting = load_settings.ArcherySettings(setting_file)
zap_api_key = ''
zap_hosts = '127.0.0.1'
zap_ports = '8080'


def zap_connect():
    all_zap = zap_settings_db.objects.all()

    zap_api_key = ''
    zap_hosts = '127.0.0.1'
    zap_ports = '8080'

    for zap in all_zap:
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port

    zap = ZAPv2(apikey=zap_api_key,
                proxies={
                    'http': zap_hosts + ':' + zap_ports,
                    'https': zap_hosts + ':' + zap_ports})

    return zap


def zap_replacer(target_url):
    zap = zap_connect()
    try:
        zap.replacer.remove_rule(description=target_url, apikey=zap_api_key)
    except Exception as e:
        print("ZAP Replacer error")

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
    false_positive = None

    """ Connect with ZAP scanner global variable """

    def __init__(self, target_url, project_id, rescan_id, rescan):
        """

        :param target_url: Target URL parameter.
        :param project_id: Project ID parameter.
        """
        self.target_url = target_url
        self.project_id = project_id
        self.rescan_id = rescan_id
        self.rescan = rescan
        self.zap = zap_connect()

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
                print("excluded url "), excluded_url
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
        print("All cookies"), all_cookies
        print("Target URL---"), self.target_url

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
            print("targets:-----"), self.target_url
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
                print("ZAP Scan Status:"), scan_status
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

    def zap_scan_result(self):
        """
        The function return ZAP Scan Results.
        :return:
        """
        try:
            all_vuln = self.zap.core.xmlreport()
        except Exception as e:
            print("zap scan result error")

        return all_vuln

    def zap_result_save(self, all_vuln, project_id, un_scanid):
        """
        The function save all data in Archery Database
        :param all_vuln:
        :param project_id:
        :param un_scanid:
        :return:
        """

        root_xml = ET.fromstring(all_vuln)
        en_root_xml = ET.tostring(root_xml, encoding='utf8').decode('ascii', 'ignore')
        root_xml_en = ET.fromstring(en_root_xml)

        zap_xml_parser.xml_parser(project_id=project_id,
                                  scan_id=un_scanid,
                                  root=root_xml_en)

        self.zap.core.delete_all_alerts()