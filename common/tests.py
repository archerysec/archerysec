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


class CommonUtilityTest(TestCase):
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

    def test_json_to_yaml(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test json-to-yaml API
        """
        json_object = {"message": "hello world"}
        form_data = {"json_object": json_object}
        # Testing with an authenticated user
        client, refresh_token = self.auth_test.login_user("admin")
        response = client.post(
            "/archerysec/api/v1/utility/json-to-yaml/", data=form_data, format="json"
        )
        if response.status_code != 200:
            self.fail("Unable to convert JSON to YAML")

        # Testing with unauthenticated user
        client = APIClient()
        response = client.post(
            "/archerysec/api/v1/utility/json-to-yaml/", data=form_data, format="json"
        )
        if response.status_code == 200:
            self.fail("API publicly accessible")

    def test_yaml_to_json(self):
        """
        This is a test method. This is automatically executed by django test

        Method is used to test yaml-to-json API
        """
        form_data = {"yaml_object": "message: hello world"}
        # Testing with an authenticated user
        client, refresh_token = self.auth_test.login_user("admin")
        response = client.post(
            "/archerysec/api/v1/utility/yaml-to-json/", data=form_data
        )
        if response.status_code != 200:
            self.fail("Unable to convert YAML to JSON")

        # Testing with unauthenticated user
        client = APIClient()
        response = client.post(
            "/archerysec/api/v1/utility/yaml-to-json/", data=form_data
        )
        if response.status_code == 200:
            self.fail("API publicly accessible")
