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

from zapv2 import ZAPv2
from django.db.models import Q
import os
import time
import uuid
import json
import ast
from archerysettings.models import zap_settings_db, burp_setting_db, openvas_setting_db
import hashlib

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
    zap.replacer.remove_rule(description=target_url, apikey=zap_api_key)

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

    # zap = zap_connect()

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
                print "excluded url ", excluded_url
        except Exception as e:
            print e

        try:
            self.zap.spider.exclude_from_scan(
                regex=excluded_url,

            )
        except Exception as e:
            print e

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
            print e
        print "All cookies", all_cookies
        print "Target URL---", self.target_url

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
            print e

    def zap_spider(self):
        """
        Scan trigger in ZAP Scanner and return Scan ID
        :return:
        """
        spider_id = ""

        try:
            print "targets:-----", self.target_url
            spider_id = self.zap.spider.scan(self.target_url)
            time.sleep(5)
            # try:
            #     self.zap.ajaxSpider.scan(self.target_url)
            # except Exception as e:
            #     print e

            save_all = zap_spider_db(
                spider_url=self.target_url,
                spider_scanid=spider_id
            )
            save_all.save()
        except Exception as e:
            print e

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
            print e

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
                # print "Spider progress", spider_status
                time.sleep(5)
        except Exception as e:
            print e

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
            print e

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
            print e

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
                print "ZAP Scan Status:", scan_status
                time.sleep(10)
                zap_scans_db.objects.filter(
                    scan_scanid=un_scanid
                ).update(vul_status=scan_status)
        except Exception as e:
            print e

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
        all_vuln = self.zap.core.alerts(self.target_url)

        return all_vuln

    def zap_result_save(self, all_vuln, project_id, un_scanid):
        """
        The function save all data in Archery Database
        :param all_vuln:
        :param project_id:
        :param un_scanid:
        :return:
        """

        for vuln in all_vuln:
            vuln_id = uuid.uuid4()
            confidence = vuln['confidence']
            wascid = vuln['wascid']
            cweid = vuln['cweid']
            risk = vuln['risk']
            reference = vuln['reference']
            url = vuln['url']
            name = vuln['name']
            solution = vuln['solution']
            param = vuln['param']
            evidence = vuln['evidence']
            sourceid = vuln['sourceid']
            pluginId = vuln['pluginId']
            other = vuln['other']
            attack = vuln['attack']
            messageId = vuln['messageId']
            method = vuln['method']
            alert = vuln['alert']
            ids = vuln['id']
            description = vuln['description']
            status = 'Open'

            global vul_col

            if risk == 'High':
                vul_col = "important"
            elif risk == 'Medium':
                vul_col = "warning"
            elif risk == 'Low':
                vul_col = "info"
            else:
                vul_col = "info"

            # date_time = datetime.datetime.now()

            dup_data = name + url + risk
            duplicate_hash = hashlib.sha1(dup_data).hexdigest()

            match_dup = zap_scan_results_db.objects.filter(
                dup_hash=duplicate_hash).values('dup_hash').distinct()
            lenth_match = len(match_dup)

            if lenth_match == 1:
                duplicate_vuln = 'Yes'
            elif lenth_match == 0:
                duplicate_vuln = 'No'
            else:
                duplicate_vuln = 'None'

            false_p = zap_scan_results_db.objects.filter(
                false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            global false_positive
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            elif lenth_match == 0:
                false_positive = 'No'
            else:
                false_positive = 'No'

            dump_all = zap_scan_results_db(
                vuln_id=vuln_id,
                vuln_color=vul_col,
                scan_id=un_scanid,
                rescan_id=self.rescan_id,
                rescan=self.rescan,
                project_id=project_id,
                confidence=confidence,
                wascid=wascid,
                cweid=cweid,
                risk=risk,
                reference=reference,
                url=url,
                name=name,
                solution=solution,
                param=param,
                evidence=evidence,
                sourceid=sourceid,
                pluginId=pluginId,
                other=other,
                attack=attack,
                messageId=messageId,
                method=method,
                alert=alert,
                ids=ids,
                description=description,
                false_positive=false_positive,
                vuln_status=status,
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln
            )

            dump_all.save()

        time.sleep(5)

        zap_all_vul = zap_scan_results_db.objects.filter(
            scan_id=un_scanid).values(
            'name',
            'risk',
            'vuln_color').distinct()

        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))
        total_duplicate = len(zap_all_vul.filter(vuln_duplicate='Yes'))

        zap_scans_db.objects.filter(
            scan_scanid=un_scanid
        ).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate
        )
        if total_vul == total_duplicate:
            zap_scans_db.objects.filter(scan_scanid=un_scanid) \
                .update(total_vul='0',
                        high_vul='0',
                        medium_vul='0',
                        low_vul='0',
                        total_dup=total_duplicate
                        )

        time.sleep(10)

        zap_web_all = zap_scan_results_db.objects.filter(scan_id=un_scanid)
        for m in zap_web_all:
            msg_id = m.messageId
            request_response = self.zap.core.message(id=msg_id)
            ja_son = json.dumps(request_response)
            ss = ast.literal_eval(ja_son)

            for key, value in ss.viewitems():
                global note
                if key == "note":
                    note = value
                global rtt
                if key == "rtt":
                    rtt = value
                global tags
                if key == "tags":
                    tags = value
                global timestamp
                if key == "timestamp":
                    timestamp = value
                global responseHeader
                if key == "responseHeader":
                    responseHeader = value
                global requestBody
                if key == "requestBody":
                    requestBody = value
                global responseBody
                if key == "responseBody":
                    responseBody = value
                global requestHeader
                if key == "requestHeader":
                    requestHeader = value
                global cookieParams
                if key == "cookieParams":
                    cookieParams = value
                global res_type
                if key == "type":
                    res_type = value
                global res_id
                if key == "id":
                    res_id = value

            zap_scan_results_db.objects.filter(
                messageId=msg_id
            ).update(
                note=note,
                rtt=rtt,
                tags=tags,
                timestamp=timestamp,
                responseHeader=responseHeader,
                requestBody=requestBody,
                responseBody=responseBody,
                requestHeader=requestHeader,
                cookieParams=cookieParams,
                res_type=res_type,
                res_id=res_id
            )
        status = "Scan Completed"
        return status
