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

from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from rest_framework import serializers

User = get_user_model()

from user_management.models import UserProfile


class UserSettingsSerializers(serializers.ModelSerializer):
    landing_page = serializers.SerializerMethodField()
    logintime = serializers.SerializerMethodField()

    def get_landing_page(self, obj):
        # compute the extra field value here
        # print(obj)
        return "test"

    def get_logintime(self, obj):
        return "time"

    class Meta:
        model = User
        fields = [
            "uu_id",
            "role",
            "image",
            "email",
            "name",
            "landing_page",
            "logintime",
        ]

    uu_id = serializers.UUIDField()
    email = serializers.EmailField(max_length=255)
    name = serializers.CharField(max_length=255)
    role = serializers.CharField(max_length=255)
    image = serializers.ImageField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["uu_id", "image", "email", "name"]

    def update(self, instance, validated_data):
        instance.email = validated_data.get("email", instance.email)
        instance.name = validated_data.get("name", instance.name)
        instance.image = validated_data.get("image", instance.image)
        instance.save()
        return instance


class ForgotPassReqSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)


class ResetPassReqSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)


class UpdtPassReqSerializer(serializers.Serializer):
    user_id = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect old password")
        return value

    def validate(self, attrs):
        if attrs["new_password1"] != attrs["new_password2"]:
            raise serializers.ValidationError("New passwords do not match")
        return attrs

    def save(self):
        request = self.context["request"]
        form = PasswordChangeForm(request.user, self.validated_data)
        if form.is_valid():
            user = form.save()
            # Updating the session with the new password hash
            update_session_auth_hash(request, user)
        return user
