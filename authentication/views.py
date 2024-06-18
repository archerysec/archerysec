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
import re
import time
from datetime import datetime

import jwt
import magic
from django.conf import settings
from django.contrib import auth, messages
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_protect
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from stronghold.decorators import public

from authentication.models import *
from authentication.serializers import *
from common.functions import current_epoch, epoch_to_date
from user_management import permissions
from user_management.models import *


# Login View
@public
@csrf_protect
def login(request):
    """
    Login Request
    :param request:
    :return:
    """
    c = {}
    c.update(request)
    return render(request, "login/login.html", c)


@public
def auth_view(request):
    """
    Authentication request.
    :param request:
    :return:
    """
    username = request.POST.get(
        "username",
        "",
    )
    password = request.POST.get(
        "password",
        "",
    )
    user = auth.authenticate(username=username, password=password)

    if user is not None:
        auth.login(request, user)
        return HttpResponseRedirect(reverse("dashboard:dashboard"))
    else:
        messages.add_message(
            request, messages.ERROR, "Please check your login details and try again."
        )
        return HttpResponseRedirect(reverse("login"))


@public
def logout(request):
    """
    Logout request
    :param request:
    :return:
    """
    auth.logout(request)
    return render(request, "logout/logout.html")


def loggedin(request):
    """
    After login request.
    :param request:
    :return:
    """
    return render(request, "webscanners/webscanner.html")


class ForgotPassword(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ForgotPassReqSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tokenInLink = get_random_string(
            length=16,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        )
        email = request.data.get("email")
        encodedToken = (
            email + "##" + str(current_epoch()) + "##" + tokenInLink
        ).encode("utf-8")

        # Update token in database
        user_detail = UserProfile.objects.filter(email=email).update(
            pass_token=tokenInLink, token_time=epoch_to_date(int(time.time()))
        )

        if user_detail != 0:
            content = {"message": "Password Recovery steps sent to registered email"}
            return Response(content, status=status.HTTP_200_OK)
        else:
            content = {"message": "User details not found"}
            return Response(content, status=status.HTTP_404_NOT_FOUND)


class ResetPassword(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ResetPassReqSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_token = request.data.get("token")
        user_password = request.data.get("password")
        invalid_token = False
        try:
            user_detail = (
                base64.urlsafe_b64decode(user_token).decode("utf-8").split("##")
            )
        except:
            invalid_token = True
        regex = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
        if invalid_token == False and re.search(regex, user_detail[0]):
            try:
                user = UserProfile.objects.get(email=user_detail[0])
                if user.pass_token == user_detail[2]:
                    user.set_password(user_password)
                    user.pass_token = None
                    user.token_time = None
                    user.save()
                    content = {"message": "Password Reset Successful"}
                else:
                    invalid_token = True
            except UserProfile.DoesNotExist:
                invalid_token = True
        else:
            invalid_token = True
        if invalid_token:
            return Response(
                {"message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST
            )
        else:
            return Response(content, status=status.HTTP_200_OK)


class UpdatePassword(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        serializer = UpdatePasswordSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            content = {"message": "Password Changed"}
            return Response(content, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserSettings(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        """
        Return User settings
        """
        user_id = request.user.id

        userssettings = (
            UserLoginHistory.objects.filter(user__id=user_id)
            .values("logintime")
            .order_by("-logintime")[:1]
        )
        login_time = userssettings[0]["logintime"]

        user = self.get_object()
        serializer = UserSettingsSerializers(user)
        data = serializer.data
        data.update({"landing_page": self.get_landing_page(data["role"])})
        data.update({"logintime": login_time})

        return Response(data, status=status.HTTP_200_OK)

    def get_landing_page(self, role):
        landing_page = {
            "Admin": "home",
            "Analyst": "scanner",
            "Viewer": "dashboard",
        }
        return landing_page[role]

    def get_object(self):
        return self.request.user

    def put(self, request, format=None):
        user = self.get_object()
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfilePictureUploadAPIView(APIView):
    """
    API endpoint that allows a user to upload their profile picture.
    """

    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, *args, **kwargs):
        if "profile_picture" not in request.data:
            raise ValidationError("Profile picture not found")
        
        user_profile = request.user
        profile_picture = request.data.get("profile_picture")

        if profile_picture:
            mime_type = magic.from_buffer(profile_picture.read(), mime=True)
            allowed_types = ["image/jpeg", "image/png"]
            if mime_type not in allowed_types:
                raise ValidationError(
                    f"File type not allowed. Allowed types: {allowed_types}"
                )

            filename = profile_picture.name
            fs = FileSystemStorage(location=settings.MEDIA_ROOT)
            uploaded_file = fs.save(
                f"user_{user_profile.uu_id}/{filename}", profile_picture
            )
            user_profile.image = uploaded_file
            user_profile.save()
            # Build the image URL
            image_url = fs.url(uploaded_file)
            return Response(
                {"detail": "Profile picture uploaded successfully", "image_url": image_url},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"detail": "No profile picture uploaded."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Update Login History
        login_history = UserLoginHistory(user=user, IP="to get")
        login_history.save()

        # Add custom claims
        token["name"] = user.name
        token["role"] = str(user.role)
        token["loginId"] = int(login_history.id)

        return token


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class Logout(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        user_id = request.user.id
        token = request.data.get("refrest-token")
        login_id_token = request.headers["Authorization"].split("Bearer ")[1]
        login_id = jwt.decode(login_id_token, options={"verify_signature": False})[
            "loginId"
        ]

        # Blacklisting token
        blackListToken = RefreshToken(token)
        print(blackListToken)
        print(blackListToken.blacklist())

        # Getting Client IP
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")

        # Updating logout time
        logout_detail = UserLoginHistory.objects.filter(id=login_id).update(
            logouttime=datetime.now(), IP=ip
        )

        content = {"message": "Logged Out"}
        return Response(content, status=status.HTTP_200_OK)
