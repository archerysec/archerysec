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

"""Author: Anand Tiwari """

import json
from django.core import signing
from archerysettings.models import zap_settings_db,\
    burp_setting_db,\
    openvas_setting_db,\
    nmap_vulners_setting_db, \
    arachni_settings_db


class SaveSettings:

    def __init__(self, setting_file):

        self.setting_file = setting_file

    def nmap_vulners(self, enabled, version, online, timing):
        """
        Save NAMP Vulners Settings into setting file.
        :param enabled:
        :param version:
        :param online:
        :param timing:
        :return:
        """
        all_nv = nmap_vulners_setting_db.objects.all()
        all_nv.delete()
        if timing > 5:
            timing = 5
        elif timing < 0:
            timing = 0

        save_nv_settings = nmap_vulners_setting_db(enabled=enabled,
                                                   version=version,
                                                   online=online,
                                                   timing=timing
                                                   )
        save_nv_settings.save()

    def save_zap_settings(self, apikey, zaphost, zaport):
        """
        Save ZAP Settings into setting file.
        :param apikey:
        :param zaphost:
        :param zaport:
        :return:
        """
        all_zap = zap_settings_db.objects.all()
        all_zap.delete()

        save_zapsettings = zap_settings_db(zap_url=zaphost,
                                           zap_api=apikey,
                                           zap_port=zaport
                                           )
        save_zapsettings.save()

    def save_burp_settings(self, burphost, burport):
        """
        Save Burp Settings into setting file.
        :param burphost:
        :param burport:
        :return:
        """

        all_burp = burp_setting_db.objects.all()
        all_burp.delete()

        save_burpsettings = burp_setting_db(burp_url=burphost,
                                            burp_port=burport
                                            )
        save_burpsettings.save()
        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                data['burp_path'] = burphost
                data['burp_port'] = burport
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        except Exception as e:
            return e
        return f.close()

    def openvas_settings(self, openvas_host, openvas_port, openvas_enabled, openvas_user, openvas_password):
        """
        Save OpenVAS Settings into Setting files.
        :param host:
        :param port:
        :param enabled:
        :param username:
        :param passwrod:
        :return:
        """

        all_openvas = openvas_setting_db.objects.all()
        all_openvas.delete()

        openvas_settings = openvas_setting_db(host=openvas_host,
                                              port=openvas_port,
                                              enabled=openvas_enabled,
                                              user=openvas_user,
                                              password=openvas_password
                                              )
        openvas_settings.save()
        try:
            with open(self.setting_file, 'r+') as f:
                sig_ov_user = signing.dumps(openvas_user)
                sig_ov_pass = signing.dumps(openvas_password)
                sig_ov_host = signing.dumps(openvas_host)
                sig_ov_port = signing.dumps(openvas_port)
                sig_ov_enabled = signing.dumps(openvas_enabled)
                data = json.load(f)
                data['open_vas_user'] = sig_ov_user
                data['open_vas_pass'] = sig_ov_pass
                data['open_vas_host'] = sig_ov_host
                data['open_vas_port'] = sig_ov_port
                data['open_vas_enabled'] = sig_ov_enabled
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()

        except Exception as e:
            return e
        return f.close()

    def save_email_settings(self, email_subject, email_from, email_to):
        """

        :param email_subject:
        :param email_from:
        :param email_to:
        :return:
        """

        try:
            with open(self.setting_file, 'r+') as f:
                data = json.load(f)
                data['email_subject'] = email_subject
                data['from_email'] = email_from
                data['to_email'] = email_to
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        except Exception as e:
            return e
        return f.close()

    def save_arachni_settings(self, arachnihost, arachniport):
        """

        :param arachnihost:
        :param arachniport:
        :return:
        """
        all_arachni = arachni_settings_db.objects.all()
        all_arachni.delete()

        save_arachnisettings = arachni_settings_db(arachni_url=arachnihost,
                                                   arachni_port=arachniport,
                                                   )
        save_arachnisettings.save()
