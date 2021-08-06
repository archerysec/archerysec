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

from rest_framework import permissions

from archeryapi.models import OrgAPIKey


class IsAdmin(permissions.BasePermission):
    """Allow for Admin only"""

    allowed_roles = ["Admin"]

    def has_permission(self, request, view):
        """Check if user with admin access"""
        return str(request.user.role) in self.allowed_roles


class IsAnalyst(permissions.BasePermission):
    """Allow for Analyst and Admin only"""

    allowed_roles = ["Admin", "Analyst"]

    def has_permission(self, request, view):
        """Check if user with Analyst access"""
        return str(request.user.role) in self.allowed_roles


class IsViewer(permissions.BasePermission):
    """Allow for Viewer, Editor and Admin only"""

    allowed_roles = ["Admin", "Analyst", "Viewer"]

    def has_permission(self, request, view):
        """Check if user with Viewer access"""
        return str(request.user.role) in self.allowed_roles


class IsSelfOrAdmin(permissions.BasePermission):
    """Allow for Self or Admin only"""

    allowed_roles = ["Admin"]

    def has_object_permission(self, request, view, obj):
        """Check if user is trying to use it's own data"""
        return (
            obj.user.id == request.user.id
            or str(request.user.role) in self.allowed_roles
        )


class IsOwnerOrAdminOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admin to edit it.
    """

    allowed_roles = ["Admin"]

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        elif str(request.user.role) in self.allowed_roles:
            return True
        else:
            # Write permissions are only allowed to the owner of the snippet.
            return obj.owner == request.user


class VerifyAPIKey(permissions.BasePermission):
    """Allow only if API Key is there"""

    def has_permission(self, request, view):
        """Check if user with admin access"""
        api_key = request.META.get("HTTP_X_API_KEY")
        key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
        if key_object is None:
            return False
        return key_object.is_active
