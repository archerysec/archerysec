from rest_framework import serializers
from .models import zap_scans_db

class WebScanSerializer(serializers.Serializer):
    scan_url = serializers.URLField(required=True, help_text=("Proper domain should be provided"))
    project_id = serializers.UUIDField(required=True, help_text=("Project ID should be provided"))
    scan_scanid = serializers.UUIDField(read_only=True)
    # vul_num = serializers.CharField(read_only=True)
    vul_status = serializers.IntegerField(read_only=True)
    total_vul = serializers.CharField(read_only=True)
    high_vul = serializers.CharField(read_only=True)
    medium_vul = serializers.CharField(read_only=True)
    low_vul = serializers.CharField(read_only=True)
    date_created = serializers.DateTimeField(read_only=True)
    date_modified = serializers.DateTimeField(read_only=True)