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

import uuid

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models


class Organization(models.Model):
    """Database model for organization in system"""

    class Meta:
        db_table = "organization"
        verbose_name_plural = "Organizations"

    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=255)
    logo = models.CharField(max_length=255)
    contact = models.CharField(max_length=255)
    token_time = models.DateTimeField(auto_now=True, null=True)
    address = models.CharField(max_length=255)

    REQUIRED_FIELDS = ["name"]

    def __unicode__(self):
        return self.name

    def get_org_name(self):
        """Retrieve full name of organization"""
        return self.name

    def __str__(self):
        """Return string representation of the organization"""
        return self.name


class UserRoles(models.Model):
    """Database model for user roles in system"""

    class Meta:
        db_table = "user_roles"
        verbose_name_plural = "User Roles"

    role = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=255)
    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    REQUIRED_FIELDS = ["role"]

    def __unicode__(self):
        return self.role

    def get_user_role(self):
        """Retrieve full name of role"""
        return self.role

    def __str__(self):
        """Return string representation of the role"""
        return self.role


class UserProfileManager(BaseUserManager):
    """Manager for user profiles"""

    def create_user(self, email, name, role, organization, password=None):
        """Create a new user profile by django cli"""
        if not email:
            raise ValueError("User must have an email address")

        email = self.normalize_email(email)
        user = self.model(email=email, name=name)
        user.role = UserRoles.objects.get(id=role)
        user.organization = Organization.objects.get(id=organization)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, role, organization, password):
        """Create a super user by django cli"""
        user = self.create_user(email, name, role, organization, password)

        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user


class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Database model for users in system"""

    class Meta:
        db_table = "user_profile"
        verbose_name_plural = "User Profiles"

    organization = models.ForeignKey(
        "Organization", on_delete=models.CASCADE, null=False
    )
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    image = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.ForeignKey("UserRoles", on_delete=models.SET_NULL, null=True)
    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    pass_token = models.CharField(max_length=255, null=True)
    token_time = models.DateTimeField(auto_now=True, null=True)
    password_updt_time = models.DateTimeField(auto_now=True, null=True)

    objects = UserProfileManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "role", "organization"]

    def get_full_name(self):
        """Retrieve full name of user"""
        return self.name

    def get_short_name(self):
        """Retrieve short name of user"""
        return self.name

    def get_profile_dp(self):
        """Retrieve short name of user"""
        return self.image

    def get_org_name(self):
        """Retrieve user's organization name"""
        return self.organization

    def __str__(self):
        """Return string representation of the user"""
        return self.email
