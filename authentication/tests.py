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
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from common.functions import current_epoch, epoch_to_date
from user_management.models import *

logging.disable(logging.CRITICAL)


class UserCreationTest(TestCase):
    fixtures = ["fixtures/default_user_roles.json"]

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
        )
        # Creating analyst User
        UserProfile.objects.create_user(
            name=self.analyst.get("name"),
            email=self.analyst.get("email"),
            password=self.analyst.get("password"),
            role=2,
        )

    def login_user(self, role):
        """
        Use this function to login before calling any API

        role: String, 'admin', 'analyst'

        Returns: APIClient and Refresh Token
        """
        client = APIClient()
        if role == "admin":
            credential = {
                "email": self.admin.get("email"),
                "password": self.admin.get("password"),
            }
        elif role == "analyst":
            credential = {
                "email": self.analyst.get("email"),
                "password": self.analyst.get("password"),
            }
        else:
            credential = {
                "email": self.analyst.get("email"),
                "password": self.analyst.get("password"),
            }
        response = client.post(
            "/archerysec/api/v1/authentication/login/", data=credential
        )
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {response.data.get("access")}')
        return client, response.data.get("refresh")

    def test_login_user(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test Login user API
        """
        client = APIClient()

        # Testing correct credentials
        credential = {
            "email": self.admin.get("email"),
            "password": self.admin.get("password"),
        }
        response = client.post(
            "/archerysec/api/v1/authentication/login/", data=credential
        )
        if not response.data.get("access") and response.status_code == 200:
            self.fail("Access token didn't generated for loggedin user")

        # Testing incorrect credentials
        credential = {
            "email": self.admin.get("email"),
            "password": self.admin.get("password") + "incorrect",
        }
        response = client.post(
            "/archerysec/api/v1/authentication/login/", data=credential
        )
        if response.status_code != 401:
            self.fail("User logged in with incorrect password")

        # Testing incorrect User
        credential = {
            "email": self.admin.get("email") + "incorrect",
            "password": self.admin.get("password"),
        }
        response = client.post(
            "/archerysec/api/v1/authentication/login/", data=credential
        )
        if response.status_code != 401:
            self.fail("User logged in with incorrect user")

    def test_forgot_password(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test Forgot Password API
        """
        client = APIClient()
        # Recovery for correct user
        credential = {"email": self.admin.get("email")}
        response = client.post(
            "/archerysec/api/v1/authentication/forgot-pass/", data=credential
        )
        if (
            response.data.get("message")
            != "Password Recovery steps sent to registered email"
        ):
            self.fail("Password recovery failed")

        # Recovery for incorrect user
        credential = {"email": self.admin.get("email") + "incorrect"}
        response = client.post(
            "/archerysec/api/v1/authentication/forgot-pass/", data=credential
        )
        if response.data.get("message") != "User details not found":
            self.fail("Password recovered for an non existing user")

    def test_refresh_token(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test Refresh auth token API
        """
        client, refresh_token = self.login_user("admin")
        refresh_token_form = {"refresh": refresh_token}
        response = client.post(
            "/archerysec/api/v1/authentication/refresh-token/", data=refresh_token_form
        )
        if not response.data.get("access") and response.status_code == 200:
            self.fail("Refreshing token failed")

    def test_user_settings(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test User Settings API
        """
        # User settings for admin user
        client, refresh_token = self.login_user("admin")
        response = client.get("/archerysec/api/v1/authentication/user-settings/")
        if response.status_code == 200:
            data = json.loads(json.dumps(response.data[0]))
            if data["landing_page"] != "pipeline-dashboard":
                self.fail("Incorrect settings for Admin user")
        else:
            self.fail("Can't fetch user settings")

        # User settings for analyst user
        client, refresh_token = self.login_user("analyst")
        response = client.get("/archerysec/api/v1/authentication/user-settings/")
        if response.status_code == 200:
            data = json.loads(json.dumps(response.data[0]))
            if data["landing_page"] != "pipeline-training":
                self.fail("Incorrect settings for analyst user")
        else:
            self.fail("Can't fetch user settings")

    def test_logout_user(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test Logout API
        """
        client, refresh_token = self.login_user("admin")
        response = client.post("/archerysec/api/v1/authentication/logout/")
        if response.status_code != 200:
            self.fail("Unable to logout user")

    def test_reset_password(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test reset password API
        """
        self.test_forgot_password()
        test_user = UserProfile.objects.get(email=self.admin.get("email"))
        form_data = {
            "token": (
                test_user.email
                + "##"
                + str(current_epoch())
                + "##"
                + test_user.pass_token
            ).encode("utf-8"),
            "password": "R3setP@ssword",
        }
        client = APIClient()
        response = client.post(
            "/archerysec/api/v1/authentication/reset-pass/", data=form_data
        )
        if response.status_code != 400:
            self.fail("Password Resetted with incorrect token")

    def test_update_password(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test update password API
        """
        client, refresh_token = self.login_user("admin")
        # Updating password of existing user
        test_user = UserProfile.objects.get(email=self.analyst.get("email"))
        form_data = {"user_id": test_user.id, "password": "N3wP@ssword"}
        self.analyst["password"] = form_data.get("password")
        response = client.post(
            "/archerysec/api/v1/authentication/update-pass/", data=form_data
        )
        if response.status_code != 200:
            self.fail("Password update failed")

        # Updating password of non existing user
        form_data = {"user_id": int(test_user.id) + 100, "password": "N3wP@ssword"}
        response = client.post(
            "/archerysec/api/v1/authentication/update-pass/", data=form_data
        )
        if response.status_code == 200:
            self.fail("Password update for non existing user")

        # Updating password without permission
        client, refresh_token = self.login_user("analyst")
        test_user = UserProfile.objects.get(email=self.admin.get("email"))
        form_data = {"user_id": test_user.id, "password": "N3wP@ssword"}
        response = client.post(
            "/archerysec/api/v1/authentication/update-pass/", data=form_data
        )
        if response.status_code != 403:
            self.fail("Password updated without permission")
