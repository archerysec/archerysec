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
from django.http import HttpResponse
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from yaml import dump, safe_load

from common.functions import current_epoch, epoch_to_date
from common.serializers import *


class Json_to_Yaml(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """
        Send Yaml as response based on the received JSON
        """
        serializer = Json_to_Yaml_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        json_object = request.data.get("json_object")
        yaml_config = dump(json_object)

        return Response(yaml_config)


class Yaml_to_Json(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        """
        Send Json as response based on the received Yaml
        """
        serializer = Yaml_to_Json_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        yaml_object = request.data.get("yaml_object")
        json_config = safe_load(yaml_object)

        return Response(json_config, status=status.HTTP_200_OK)
