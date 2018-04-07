#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
#/_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

""" Author: Anand Tiwari """
import os
import json
from django.core import signing


class ArcherySettings:

    def __init__(self, setting_file):
        self.setting_file = setting_file

    def zap_api_key(self):
        """
        Loading ZAP API Key from setting file.
        :return:
        """
        apikey = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                load_api_key = data['zap_api_key']
                apikey = signing.loads(load_api_key)
        except Exception as e:
            print e

        return apikey

    def zap_host(self):
        """
        Loading ZAP Host from setting file.
        :return:
        """
        zapath = None
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                zapath = data['zap_path']

        except Exception as e:
            print e
        return zapath

    def zap_port(self):
        """
        Loading ZAP Port from setting file.
        :return:
        """
        zaport = None
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                zaport = data['zap_port']

        except Exception as e:
            print "Error in setting file as", e
        return zaport

    def burp_host(self):
        """
        Loading Burp Host address from setting file.
        :return:
        """
        burphost = None
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                burphost = data['burp_path']
        except Exception as e:
            print "Error in setting file as", e

        return burphost

    def burp_port(self):
        """
        Loading Burp port from setting file.
        :return:
        """
        burport = None
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                burport = data['burp_port']
        except Exception as e:
            print "Error in setting file as", e

        return burport

    def openvas_host(self):
        """
        Loading OpenVAS Setting from setting file.
        :return:
        """
        openvashost = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                openvashost = data['open_vas_ip']
        except Exception as e:
            print "Error in setting file as", e

        return openvashost

    def openvas_username(self):
        """
        Loading OpenVAS Username from setting file.
        :return:
        """
        openvas_username = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                openvas_username = data['open_vas_user']
        except Exception as e:
            print "Error in setting file as", e

        return openvas_username

    def openvas_pass(self):
        """
        Loading OpenVAS Password from setting file.
        :return:
        """
        openvas_password = None

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                openvas_password = data['open_vas_pass']
        except Exception as e:
            print "Error in setting file as", e

        return openvas_password

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
            print "Error in setting file as", e

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
            print "Error in setting file as", e

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
            print "Error in setting file as", e

        return emails_to