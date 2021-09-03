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

from django.contrib.auth import get_user_model
from rest_framework import serializers

from user_management.models import UserProfile


class UserCreatReqSerializers(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    organization = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)


class UserProfileSerializers(serializers.Serializer):
    uu_id = serializers.CharField(max_length=255)
    email = serializers.EmailField(max_length=255)
    organization = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    image = serializers.CharField(max_length=255)
    is_active = serializers.BooleanField()
    is_staff = serializers.BooleanField()
    password_updt_time = serializers.DateTimeField()


class UserProfilePutReqSerializers(serializers.Serializer):
    password = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)
    image = serializers.CharField(max_length=255)


ROLE_CHOICES = (
    ("1", "Admin"),
    ("2", "Analyst"),
    ("3", "Viewer"),
)

B_CHOICES = (("True", "Active"), ("Flase", "Deactive"))


class UserPutReqSerializers(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(
        max_length=100, style={"input_type": "password", "placeholder": "Password"}
    )
    name = serializers.CharField(max_length=255)
    # role = serializers.ChoiceField(choices=ROLE_CHOICES)
    image = serializers.CharField(max_length=255, allow_null=True)


class UserRoleSerializers(serializers.Serializer):
    role = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
    uu_id = serializers.CharField(max_length=255)


class OrganizationSerializers(serializers.Serializer):
    uu_id = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
    logo = serializers.CharField(max_length=255)
    contact = serializers.CharField(max_length=255)
    address = serializers.CharField(max_length=255)


class CreateOrganizationSerializers(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255)
