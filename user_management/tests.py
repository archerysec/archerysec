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
from django.contrib.auth.hashers import make_password
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.tests import UserCreationTest
from user_management.models import *

logging.disable(logging.CRITICAL)


class UserManagementTest(TestCase):
    fixtures = ["fixtures/default_user_roles.json"]

    auth_test = UserCreationTest()

    def setUp(self):
        """
        This is the class which runs at the start before running test case.
        This method updates password of admin user
        """
        # Creating Admin user
        UserProfile.objects.create_user(
            name=self.auth_test.admin.get("name"),
            email=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
            role=1,
        )

    def test_profile(self):
        """
        This is a test method. This is automatically executed by django test
        Method is used to test profile API
        """
        # Testing with an authenticated user
        client, refresh_token = self.auth_test.login_user("admin")
        response = client.get("/archerysec/api/v1/user/profile/")
        if response.data.get("name") != self.auth_test.admin.get("name"):
            self.fail("Unable to fetch user profile")

    def test_users(self):
        """
        This is a test method. This is automatically executed by django test
        Method is used to test users API
        """
        new_user = {
            "name": "newUser",
            "email": "new_user@archerysec.com",
            "password": "n3warcherysec",
            "role": 1,
        }
        new_user_uuid = ""
        updated_name = "New User"
        user_details = ""

        # Creating user by post call
        client, refresh_token = self.auth_test.login_user("admin")
        response = client.post("/archerysec/api/v1/user/users/", data=new_user)
        if response.data.get("user_id"):
            new_user_uuid = str(response.data.get("user_id"))
        else:
            self.fail("Unable to create user by post call")

        # Fetching user details by get call
        response = client.get(f"/archerysec/api/v1/user/users/{new_user_uuid}/")
        if response.data.get("name") != new_user.get("name"):
            self.fail("Unable to fetch user details by get call")
        else:
            user_details = response.data

        # Editing user details by Put call
        user_details["role"] = 1
        user_details["name"] = updated_name
        user_details["image"] = "a"
        user_details["password"] = new_user.get("password")
        user_details.pop("password_updt_time", None)
        response = client.put(
            f"/archerysec/api/v1/user/users/{new_user_uuid}/", data=user_details
        )
        if response.status_code == 200:
            updated_user_detail = client.get(
                f"/archerysec/api/v1/user/users/{new_user_uuid}/"
            )
            if updated_user_detail.data.get("name") != updated_name:
                self.fail("Updating user failed with status successful")
        else:
            self.fail("Unable to update user details")

        # Deleting user details by delete call
        response = client.delete(f"/archerysec/api/v1/user/users/{new_user_uuid}/")
        if response.status_code == 200:
            user_check = client.get(f"/archerysec/api/v1/user/users/{new_user_uuid}/")
            if user_check.status_code != 404:
                self.fail("User details are present even after delete call")
        else:
            self.fail("Unable to delete user details by delete call")