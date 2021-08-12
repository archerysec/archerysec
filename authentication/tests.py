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

import base64
import json
import logging
import unittest

from django.test import Client, TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from common.functions import current_epoch, epoch_to_date
from user_management.models import *

logging.disable(logging.CRITICAL)


class UserCreationTest(TestCase):
    fixtures = [
        "fixtures/default_user_roles.json",
        "fixtures/default_organization.json",
    ]

    admin = {
        "name": "ArcherysecAdmin",
        "email": "archerysecadmin@archerysec.com",
        "password": "@DminArcherysec",
    }

    analyst = {
        "name": "Analyst",
        "email": "analyst@archerysec.com",
        "password": "V@lidatorArcherysec",
    }

    viewer = {
        "name": "viewer",
        "email": "viewer@archerysec.com",
        "password": "viewer@lidatorArcherysec",
    }

    def setUp(self):
        """
        This is the class which runs at the start before running test case.
        This method creates users
        """
        # Creating Admin user
        UserProfile.objects.create_user(
            name=self.admin.get("name"),
            email=self.admin.get("email"),
            password=self.admin.get("password"),
            role=1,
            organization=1,
        )
        # Creating analyst User
        UserProfile.objects.create_user(
            name=self.analyst.get("name"),
            email=self.analyst.get("email"),
            password=self.analyst.get("password"),
            role=2,
            organization=1,
        )

        # Create viewer user
        UserProfile.objects.create_user(
            name=self.viewer.get("name"),
            email=self.viewer.get("email"),
            password=self.viewer.get("password"),
            role=3,
            organization=1,
        )

    def login_user(self, role):
        """
        Use this function to login before calling any API
        role: String, 'admin', 'analyst'
        Returns: APIClient and Refresh Token
        """
        client = Client()
        if role == "admin":
            login = client.login(
                username=self.admin.get("email"), password=self.admin.get("password")
            )

        elif role == "analyst":
            login = client.login(
                username=self.analyst.get("email"),
                password=self.analyst.get("password"),
            )
        else:
            login = client.login(
                username=self.viewer.get("email"), password=self.viewer.get("password")
            )
        return client, login

    def test_login_user(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test Login user API
        """
        client = Client()

        # Testing correct credentials
        response = client.login(
            username=self.admin.get("email"), password=self.admin.get("password")
        )
        if not response == True:
            self.fail("Access token didn't generated for loggedin user")

        # Testing incorrect credentials
        response = client.login(
            username=self.admin.get("email"),
            password=self.admin.get("password") + "incorrect",
        )
        if not response == False:
            self.fail("User logged in with incorrect password")

        # Testing incorrect User
        response = client.login(
            username=self.admin.get("email") + "incorrect",
            password=self.admin.get("password"),
        )
        if not response == False:
            self.fail("User logged in with incorrect user")

    def test_after_login(self):
        """
        This is a test after login page
        """
        client = Client()

        # Try to login into application
        credential = {
            "username": self.admin.get("email"),
            "password": self.admin.get("password"),
        }

        response = client.post("/auth/auth/", credential)
        self.assertRedirects(response, "/dashboard/")


class LoginTestCase(TestCase):
    def test_login(self):
        # First check for the default behavior
        response = self.client.get("/dashboard/")
        self.assertRedirects(response, "/auth/login/?next=/dashboard/")

        # Then override the LOGIN_URL setting
        with self.settings(LOGIN_URL="/auth/login/"):
            response = self.client.get("/dashboard/")
            self.assertRedirects(response, "/auth/login/?next=/dashboard/")
