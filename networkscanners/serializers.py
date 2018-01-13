from rest_framework import serializers
from networkscanners.models import scan_save_db


class NetworkScanSerializer(serializers.Serializer):
    scan_ip = serializers.IPAddressField(required=True, help_text=("Network IP should be provided"))
    project_id = serializers.UUIDField(required=True, help_text=("Project ID should be provided"))
    target_id = serializers.UUIDField(read_only=True)
    scan_id = serializers.UUIDField(read_only=True)
    scan_status = serializers.CharField(read_only=True)
    total_vul = serializers.CharField(read_only=True)
    high_total = serializers.CharField(read_only=True)
    medium_total = serializers.CharField(read_only=True)
    low_total = serializers.CharField(read_only=True)
    date_created = serializers.DateTimeField(read_only=True)
    date_modified = serializers.DateTimeField(read_only=True)
