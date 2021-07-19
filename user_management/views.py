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


from django.contrib.auth.hashers import make_password
from django.contrib import messages
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.renderers import TemplateHTMLRenderer
from django.shortcuts import get_object_or_404

from user_management import permissions
from user_management.models import *
from user_management.serializers import *


class UsersList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'users/list_users.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_profile = UserProfile.objects.all()
            serialized_data = UserProfileSerializers(user_profile, many=True)
        else:
            try:
                user_profile = UserProfile.objects.get(uu_id=uu_id)
                serialized_data = UserProfileSerializers(user_profile, many=False)
            except UserProfile.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response({'serializer': serialized_data, 'all_users': user_profile})

    def post(self, request):
        try:
            user_id = request.data.get("user_id")
            user_profile = UserProfile.objects.get(uu_id=user_id)
            user_profile.delete()
            messages.success(request, "User Deleted")
            return HttpResponseRedirect('/users/list_user/')
        except UserProfile.DoesNotExist:
            messages.error(request, "User Doesn't Exist")
            return HttpResponseRedirect('/users/list_user/')


class UsersEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'users/edit_user.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        org = Organization.objects.all()
        if uu_id == None:
            user_details = UserProfile.objects.all()
            serialized_data = UserPutReqSerializers(user_details, many=True)
        else:
            try:
                user_details = UserProfile.objects.get(uu_id=uu_id)
                serialized_data = UserPutReqSerializers(user_details, many=False)
            except UserProfile.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response({'serializer': serialized_data, 'user_details': user_details, 'org': org})

    def post(self, request, uu_id):
        serializer = UserPutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        password = make_password(request.data.get("password"))
        role = request.data.get("role")
        name = request.data.get("name")
        image = request.data.get("image")
        organization = request.data.get("organization")
        user_profile = UserProfile.objects.filter(uu_id=uu_id).update(
            email=email,
            password=password,
            role=role,
            name=name,
            image=image,
            organization=organization
        )
        if user_profile > 0:
            return HttpResponseRedirect(
                '/users/list_user/'
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class UsersAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'users/add_user.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        org = Organization.objects.all()

        return Response({'org': org})

    def post(self, request):
        serializer = UserCreatReqSerializers(data=request.data)
        serializer.is_valid()

        email = request.data.get("email")
        organization = request.data.get("organization")
        password = request.data.get("password")
        role = request.data.get("role")
        name = request.data.get("name")

        user_exist = UserProfile.objects.filter(email=email).exists()
        if user_exist:
            messages.error(request, "User Already Exist")
            content = {"message": "User Already Exist"}
            return HttpResponseRedirect('/users/list_user/')
        else:
            UserProfile.objects.create_user(
                email, name, role, organization, password
            )
            messages.success(request, "User Created")
            return HttpResponseRedirect('/users/list_user/')


class Profile(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'profile/profile.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsOwnerOrAdminOnly,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        id = request.user.id
        user_profile = UserProfile.objects.filter(id=id)
        serializer = UserProfileSerializers(user_profile)
        return Response({'serializer': serializer, 'profiles': user_profile})

    def put(self, request, uu_id):
        serializer = UserProfilePutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = make_password(request.data.get("password"))
        name = request.data.get("name")
        image = request.data.get("image")

        id = request.user.id

        user_profile = UserProfile.objects.filter(id=id).update(
            password=password,
            name=name,
            image=image,
        )
        if user_profile > 0:
            return Response(
                {"message": "User Profile Updated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class Roles(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsViewer,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_role = UserRoles.objects.all()
            serialized_data = UserRoleSerializers(user_role, many=True)
        else:
            try:
                user_role = UserRoles.objects.get(uu_id=uu_id)
                serialized_data = UserRoleSerializers(user_role, many=False)
            except UserRoles.DoesNotExist:
                return Response(
                    {"message": "User Role Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)


class OrganizationDetail(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'organization/org_list.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        organization = Organization.objects.all()
        serialized_data = OrganizationSerializers(organization, many=False)
        return Response({'serializer': serialized_data, 'organization': organization})

    # Delete Organizaiton Functionality
    # def post(self, request):
    #     try:
    #         org_id = request.data.get("org_id")
    #         org_profile = Organization.objects.get(uu_id=org_id)
    #         org_profile.delete()
    #         return HttpResponseRedirect('/users/list_org/')
    #     except Organization.DoesNotExist:
    #         return Response(
    #             {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
    #         )


class OrgAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'organization/org_add.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        org = Organization.objects.all()

        return Response({'org': org})

    def post(self, request):
        serializer = OrganizationSerializers(data=request.data)
        serializer.is_valid()

        name = request.data.get("name")
        description = request.data.get("description")

        save_org = Organization(
            name=name, description=description
        )
        save_org.save()
        return HttpResponseRedirect('/users/list_org/')


class OrgEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'organization/org_edit.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            org_details = Organization.objects.get(uu_id=uu_id)
            serialized_data = CreateOrganizationSerializers(org_details, many=True)
        else:
            try:
                org_details = Organization.objects.get(uu_id=uu_id)
                serialized_data = CreateOrganizationSerializers(org_details, many=False)
            except UserProfile.DoesNotExist:
                return Response(
                    template_name='error/404.html')
        return Response({'serializer': serialized_data, 'org_details': org_details})

    def post(self, request, uu_id):
        serializer = CreateOrganizationSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("name")
        description = request.data.get("description")
        org_add = Organization.objects.filter(uu_id=uu_id).update(
            name=name,
            description=description,
        )
        if org_add > 0:
            return HttpResponseRedirect(
                '/users/list_org/'
            )
        else:
            return Response(
                {"message": "Org Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )
