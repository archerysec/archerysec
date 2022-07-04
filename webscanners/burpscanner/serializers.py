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


class BurpScansSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    project_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))


class BurpSettingsSerializer(serializers.Serializer):
    burp_api_key = serializers.CharField()
    burp_host = serializers.CharField()
    burp_port = serializers.IntegerField()
