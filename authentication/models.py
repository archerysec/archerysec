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

from django.conf import settings
from django.db import models

from user_management.models import UserProfile


class UserLoginHistory(models.Model):
    """Class for User Login History"""

    class Meta:
        db_table = "user_login_history"
        verbose_name_plural = "User Login Histories"

    user = models.ForeignKey(
        UserProfile, related_name="login_user", on_delete=models.CASCADE
    )
    logintime = models.DateTimeField(auto_now=True)
    logouttime = models.DateTimeField(null=True)
    IP = models.CharField(max_length=20)

    def __str__(self):
        return self.user.email + " " + str(self.logintime)
