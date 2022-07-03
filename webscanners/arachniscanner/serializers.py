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


class ArachniScansSerializer(serializers.Serializer):
    url = serializers.URLField(read_only=True)
    project_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))


class ArachniSettingsSerializer(serializers.Serializer):
    arachni_hosts = serializers.CharField()
    arachni_ports = serializers.IntegerField()
    arachni_user = serializers.CharField()
    arachni_pass = serializers.CharField()
