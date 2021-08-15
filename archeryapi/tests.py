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

import logging

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase

from authentication.tests import UserCreationTest
from projects.models import *
from webscanners.models import *
from archeryapi.models import *
from rest_framework.test import APIClient

logging.disable(logging.CRITICAL)


class APIKeyTest(TestCase):
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
    def test_api_key_page(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # create access key
        response = client.get("/api/access-key/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "access-key/access-key-list.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # create viewer key
        response = client.get("/api/access-key/")
        self.assertEqual(response.status_code, 403)

        # from admin users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # create access key
        response = client.get("/api/access-key/")
        self.assertEqual(response.status_code, 403)

    def test_api_key_create(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # create access key
        response = client.post("/api/access-key/", data={'name': 'test'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, '/api/access-key/')

        # api_key = OrgAPIKey.objects.filter(name='test').values('api_key').get['api_key']

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # create access key
        response = client.post("/api/access-key/", data={'name': 'test'})
        self.assertEqual(response.status_code, 403)

        # from viewer users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # create access key
        response = client.post("/api/access-key/", data={'name': 'test'})
        self.assertEqual(response.status_code, 403)


class APICreateProject(TestCase):
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

    def create_api_key(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # create access key
        response = client.post("/api/access-key/", data={'name': 'test'})
        self.assertEqual(response.status_code, 302)

        api_key = OrgAPIKey.objects.filter(name='test').values('api_key').get()['api_key']

        return api_key

    # Test user profile page
    def test_api_create_project(self):
        client = Client()

        api_key = self.create_api_key()

        header = {'HTTP_X_API_KEY': api_key}

        response = client.post('/api/v1/project-create/',
                               content_type='application/json',
                               data={'project_name': 'test', 'project_disc': 'test'}, **header)

        message = response.data.get("message")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(message, 'Project Created')
