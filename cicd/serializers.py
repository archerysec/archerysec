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


class CreatePoliciesSerializers(serializers.Serializer):
    name = serializers.CharField(max_length=255),
    threshold = serializers.CharField(max_length=255),
    threshold_count = serializers.CharField(max_length=255),
    scm_server = serializers.CharField(max_length=255),
    build_server = serializers.CharField(max_length=255),
    target_name = serializers.CharField(max_length=255),
    scanner = serializers.CharField(max_length=255),
    command = serializers.CharField(max_length=255),