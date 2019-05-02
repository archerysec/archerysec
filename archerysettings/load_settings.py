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

""" Author: Anand Tiwari """
import os
import json
from django.core import signing
from archerysettings.models import zap_settings_db, burp_setting_db, openvas_setting_db, nmap_vulners_setting_db


class ArcherySettings:

    def __init__(self, setting_file):
        self.setting_file = setting_file

    def zap_api_key(self):
        """
        Loading ZAP API Key from setting file.
        :return:
        """
        apikey = None

        all_zap = zap_settings_db.objects.all()

        for zap in all_zap:
            apikey = zap.zap_api

        # try:
        #     with open(self.setting_file, 'r+') as f:
        #         data = json.load(f)
        #         load_api_key = data['zap_api_key']
        #         apikey = signing.loads(load_api_key)
        # except Exception as e:
        #     print e

        return apikey

    def zap_host(self):
        """
        Loading ZAP Host from setting file.
        :return:
        """
        zapath = None

        all_zap = zap_settings_db.objects.all()

        for zap in all_zap:
            zapath = zap.zap_url

        return zapath

    def zap_port(self):
        """
        Loading ZAP Port from setting file.
        :return:
        """
        zaport = None

        all_zap = zap_settings_db.objects.all()

        for zap in all_zap:
            zaport = zap.zap_port

        return zaport

    def burp_api_key(self):
        """
        Loading Burp Host address from setting file.
        :return:
        """
        burpapikey = None

        all_burp = burp_setting_db.objects.all()

        for burp in all_burp:
            burpapikey = burp.burp_api_key

        return burpapikey

    def burp_host(self):
        """
        Loading Burp Host address from setting file.
        :return:
        """
        burphost = None

        all_burp = burp_setting_db.objects.all()

        for burp in all_burp:
            burphost = burp.burp_url

        return burphost

    def burp_port(self):
        """
        Loading Burp port from setting file.
        :return:
        """
        burport = None

        all_burp = burp_setting_db.objects.all()

        for burp in all_burp:
            burport = burp.burp_port

        return burport

    def openvas_host(self):
        """
        Loading OpenVAS Setting from setting file.
        :return:
        """
        openvas_host = None

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            openvas_host = openvas.host

        # try:
        #     with open(self.setting_file, 'r+') as f:
        #         data = json.load(f)
        #         openvashost = data['open_vas_host']
        # except Exception as e:
        #     print "Error in setting file as", e

        return openvas_host
 
    def openvas_username(self):
        """
        Loading OpenVAS Username from setting file.
        :return:
        """
        openvas_username = None

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            openvas_username = openvas.user

        # try:
        #     with open(self.setting_file, 'r+') as f:
        #         data = json.load(f)
        #         openvas_username = data['open_vas_user']
        # except Exception as e:
        #     print "Error in setting file as", e

        return openvas_username

    def openvas_pass(self):
        """
        Loading OpenVAS Password from setting file.
        :return:
        """
        openvas_password = None

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            openvas_password = openvas.password


        return openvas_password

    def openvas_port(self):
        openvas_port = None

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            openvas_port = openvas.port
        if not isinstance(openvas_port, int):
            openvas_port=9390
        return openvas_port

    def openvas_enabled(self):
        openvas_enabled = None

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            openvas_enabled = openvas.enabled
        if not isinstance(openvas_enabled, bool):
            openvas_enabled = False 
        return openvas_enabled

    def email_subject(self):
        """
        Load Email Subject from setting file.
        :return:
        """
        email_sub = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                email_sub = data['email_subject']
        except Exception as e:
            print("Error in setting file as", e)

        return email_sub

    def email_from(self):
        """

        :return:
        """

        emails_from = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                emails_from = data['from_email']
        except Exception as e:
            print("Error in setting file as"), e

        return emails_from

    def email_to(self):
        """

        :return:
        """
        emails_to = None
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                emails_to = data['to_email']
        except Exception as e:
            print("Error in setting file as", e)

        return emails_to

    def nv_enabled(self):
        nv_enabled = False

        all_nv = nmap_vulners_setting_db.objects.all()

        for nv in all_nv:
            nv_enabled = nv.enabled
        print(nv_enabled)
        if not isinstance(nv_enabled, bool):
            nv_enabled=False
        return nv_enabled

    def nv_version(self):
        nv_version = False

        all_nv = nmap_vulners_setting_db.objects.all()

        for nv in all_nv:
            nv_version = nv.version
        print(nv_version)
        if not isinstance(nv_version, bool):
            nv_version=False
        return nv_version

    def nv_online(self):
        nv_online = False

        all_nv = nmap_vulners_setting_db.objects.all()

        for nv in all_nv:
            nv_online = nv.online
        print(nv_online)
        if not isinstance(nv_online, bool):
            nv_online=False
        return nv_online

    def nv_timing(self):
        nv_timing = 0

        all_nv = nmap_vulners_setting_db.objects.all()

        for nv in all_nv:
            nv_timing = nv.timing
        if not isinstance(nv_timing, int):
            nv_timing=0
        if nv_timing > 5:
            nv_timing = 5
        elif nv_timing < 0:
            nv_timing = 0
        return nv_timing

