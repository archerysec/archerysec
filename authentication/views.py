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
import jwt
import re
import time
from datetime import datetime
from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from authentication.models import *
from authentication.serializers import *
from common.functions import current_epoch, epoch_to_date
from user_management import permissions
from user_management.models import *


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
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def post(self, request):
        serializer = UpdtPassReqSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_id = request.data.get("user_id")
        user_password = request.data.get("password")

        try:
            user = UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            return Response(
                {"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND
            )
        if user:
            user.set_password(user_password)
            user.save()
        return Response({"message": "Password Updated"}, status=status.HTTP_200_OK)


class UserSettings(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        """
        Return User settings
        """
        user_id = request.user.id

        userSettings = (
            UserLoginHistory.objects.filter(user__id=user_id)
            .values(
                "user__uu_id",
                "user__email",
                "user__name",
                "user__role__role",
                "logintime",
            )
            .order_by("-logintime")[:1]
        )

        serialized_data = UserSettingsSerializers(userSettings, many=True)
        serialized_data.data[0]["landing_page"] = self.get_landing_page(
            serialized_data.data[0]["role"]
        )

        return Response(serialized_data.data, status=status.HTTP_200_OK)

    def get_landing_page(self, role):
        landing_page = {
            "Admin": "home",
            "Analyst": "scanner",
            "Viewer": "dashboard",
        }
        return landing_page[role]


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
        login_id = jwt.decode(login_id_token, verify=False)["loginId"]

        # Blacklisting token
        blackListToken = RefreshToken(token)
        blackListToken.blacklist()

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
