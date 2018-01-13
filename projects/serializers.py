from rest_framework import serializers
from projects.models import project_db


class ProjectDataSerializers(serializers.Serializer):
    project_id = serializers.UUIDField(read_only=True)
    project_name = serializers.CharField(required=True, help_text=("Project Name"))
    project_disc = serializers.CharField(required=True, help_text=("Project Description"))
    project_start = serializers.DateField(required=False, help_text=("Project start date"))
    project_end = serializers.DateField(required=False, help_text=("Project End date"))
    project_owner = serializers.CharField(required=False, help_text=("Project Owner"))
