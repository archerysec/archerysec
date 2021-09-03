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
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.
import uuid

from django.conf import settings
from django.db import models
from rest_framework import permissions

from user_management.models import Organization, UserProfile

# Create your models here.


class OrgAPIKey(models.Model):
    """ Class for Organization API Keys Model """

    class Meta:
        db_table = "org_apikey"
        verbose_name_plural = "Organization API Keys"

    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    api_key = models.CharField(max_length=255)
    name = models.CharField(max_length=255, null=True)
    created_time = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        UserProfile, related_name="key_creator", on_delete=models.SET_NULL, null=True
    )
    is_active = models.BooleanField(default=True)


class VerifyAPIKey(permissions.BasePermission):
    """Allow only if API Key is there"""

    def has_permission(self, request, view):
        """Check if user with admin access"""
        api_key = request.META.get("HTTP_X_API_KEY")
        key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
        if key_object is None:
            return False
        return key_object.is_active
