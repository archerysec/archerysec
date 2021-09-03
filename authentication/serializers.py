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

from user_management.models import UserProfile


class UserSettingsSerializers(serializers.Serializer):
    id = serializers.CharField(max_length=255, source="user__uu_id")
    email = serializers.EmailField(max_length=255, source="user__email")
    name = serializers.CharField(max_length=255, source="user__name")
    role = serializers.CharField(max_length=255, source="user__role__role")
    logintime = serializers.DateTimeField()


class ForgotPassReqSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)


class ResetPassReqSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)


class UpdtPassReqSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)
