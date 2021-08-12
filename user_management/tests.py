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
from django.urls import reverse
from django.test import Client

from authentication.tests import UserCreationTest
from user_management.models import *

logging.disable(logging.CRITICAL)


class UserManagementTest(TestCase):
    fixtures = [
        "fixtures/default_user_roles.json",
        "fixtures/default_organization.json",
    ]

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
            organization=1,
        )

        # Creating analyst User
        UserProfile.objects.create_user(
            name=self.auth_test.analyst.get("name"),
            email=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
            role=2,
            organization=1,
        )

        # Create viewer user
        UserProfile.objects.create_user(
            name=self.auth_test.viewer.get("name"),
            email=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
            role=3,
            organization=1,
        )

    # Test user profile page
    def test_user_profile(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/users/profile/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "profile/profile.html")

    # Test users list page access from admin user
    def test_users_list_for_admin(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )
        response = client.get("/users/list_user/")
        self.assertEqual(response.status_code, 200)

    # Test analyst user should not have access on list user page
    def test_users_list_for_analyst_users(self):
        client = Client()
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )
        response = client.get("/users/list_user/")
        self.assertEqual(response.status_code, 403)

    # Test viewer user should not have access on list user page
    def test_users_list_for_viewer_users(self):
        client = Client()
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )
        response = client.get("/users/list_user/")
        self.assertEqual(response.status_code, 403)

    # Teat adding user functionality
    def test_add_user(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # create new user
        data = {
            "name": "test",
            "email": "test@admin.com",
            "password": "test@123",
            "role": 1,
            "organization": 1,
        }

        # send request to create new user
        response = client.post("/users/add_user/", data)
        user_id = (
            UserProfile.objects.filter(email=data.get("email"))
            .values("uu_id")
            .get()["uu_id"]
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/users/list_user/")

        credential = {
            "username": data.get("email"),
            "password": data.get("password"),
        }
        response = client.post("/auth/auth/", credential)
        self.assertRedirects(response, "/dashboard/")

        # Test delete user from database
        response_delete = client.post("/users/list_user/", data={"user_id": user_id})
        self.assertEqual(response_delete.status_code, 302)

        # Test try to login with deleted user
        response = client.post("/auth/auth/", credential)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/auth/login/")


class OrgManagementTest(TestCase):
    fixtures = [
        "fixtures/default_user_roles.json",
        "fixtures/default_organization.json",
    ]

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
            organization=1,
        )

        # Creating analyst User
        UserProfile.objects.create_user(
            name=self.auth_test.analyst.get("name"),
            email=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
            role=2,
            organization=1,
        )

        # Create viewer user
        UserProfile.objects.create_user(
            name=self.auth_test.viewer.get("name"),
            email=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
            role=3,
            organization=1,
        )

    def test_org_list(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # admin user should have access on list organization
        response = client.get("/users/list_org/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "organization/org_list.html")

        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # analyst user should not have access on list organization
        response = client.get("/users/list_org/")
        self.assertEqual(response.status_code, 403)

        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # viewer user should not have access on list organization
        response = client.get("/users/list_org/")
        self.assertEqual(response.status_code, 403)

    def test_org_add(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # admin user should have access on add organization
        response = client.post(
            "/users/add_org/", data={"name": "test", "description": "test"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/users/list_org/")

        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # analyst user should not have access on add organization
        response = client.post(
            "/users/add_org/", data={"name": "test", "description": "test"}
        )
        self.assertEqual(response.status_code, 403)

        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # viewer user should not have access on add organization
        response = client.post(
            "/users/add_org/", data={"name": "test", "description": "test"}
        )
        self.assertEqual(response.status_code, 403)

    def test_org_edit(self):
        client = Client()
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # admin user should have access on add organization
        client.post("/users/add_org/", data={"name": "test1", "description": "test"})

        get_new_org_id = (
            Organization.objects.filter(name="test1").values("uu_id").get()["uu_id"]
        )

        # admin user should have access on edit orgaization

        response = client.post(
            "/users/edit_org/" + str(get_new_org_id) + "/",
            data={"name": "test", "description": "test"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/users/list_org/")

        # analyst user should not have access on edit orgaization
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )
        response = client.post(
            "/users/edit_org/" + str(get_new_org_id) + "/",
            data={"name": "test", "description": "test"},
        )
        self.assertEqual(response.status_code, 403)

        # viewer user should not have access on edit orgaization
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )
        response = client.post(
            "/users/edit_org/" + str(get_new_org_id) + "/",
            data={"name": "test", "description": "test"},
        )
        self.assertEqual(response.status_code, 403)
