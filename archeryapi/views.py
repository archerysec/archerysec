from rest_framework.response import Response
from webscanners.models import zap_scans_db, zap_scan_results_db
from networkscanners.models import scan_save_db, ov_scan_result_db
from projects.models import project_db
from webscanners.serializers import WebScanSerializer, WebScanResultSerializer
from rest_framework import status
from webscanners import web_views
from networkscanners import views
from networkscanners.serializers import NetworkScanSerializer, NetworkScanResultSerializer
from rest_framework import generics
import uuid
from projects.serializers import ProjectDataSerializers


class WebScan(generics.ListCreateAPIView):
    queryset = zap_scans_db.objects.all()
    serializer_class = WebScanSerializer

    def get(self, request, format=None, **kwargs):
        """
            GET List all scans and check status.
        """
        all_scans = zap_scans_db.objects.all()
        serialized_scans = WebScanSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
        Launch scans using this api
        """
        serializer = WebScanSerializer(data=request.data)
        if serializer.is_valid():
            target_url = request.data.get('scan_url', )
            project_id = request.data.get('project_id', )
            web_views.launch_web_scan(target_url, project_id)

            if not target_url:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Completed"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetworkScan(generics.ListCreateAPIView):
    """
    Network Scan API call to perform scan.
    """
    queryset = scan_save_db.objects.all()
    serializer_class = NetworkScanSerializer

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = scan_save_db.objects.all()
        serialized_scans = NetworkScanSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
           Current user's identity endpoint.

        """
        serializer = NetworkScanSerializer(data=request.data)
        if serializer.is_valid():
            target_ip = request.data.get('scan_ip', )
            project_id = request.data.get('project_id', )
            profile = None
            views.Scan_Launch(target_ip, project_id, profile)
            if not target_ip:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Started"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Project(generics.CreateAPIView):

    queryset = project_db.objects.all()
    serializer_class = ProjectDataSerializers

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = project_db.objects.all()
        serialized_scans = ProjectDataSerializers(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
           Current user's identity endpoint.

        """
        serializer = ProjectDataSerializers(data=request.data)
        if serializer.is_valid():
            project_id = uuid.uuid4()
            project_name = request.data.get("project_name",)
            project_start = request.data.get("project_start",)
            project_end = request.data.get("project_end",)
            project_owner = request.data.get("project_owner",)
            project_disc = request.data.get("project_disc",)
            save_project = project_db(project_name=project_name, project_id=project_id,
                                      project_start=project_start, project_end=project_end,
                                      project_owner=project_owner, project_disc=project_disc, )
            save_project.save()

            if not project_name:
                return Response({"error": "No name passed"})
            return Response({"message": "Project Created"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WebScanResult(generics.ListCreateAPIView):
    queryset = zap_scan_results_db.objects.all()
    serializer_class = WebScanResultSerializer

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = WebScanResultSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get('scan_id',)
            # project_id = request.data.get('project_id',)
            all_scans = zap_scan_results_db.objects.filter(scan_id=scan_id)
            serialized_scans = WebScanResultSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


class NetworkScanResult(generics.ListCreateAPIView):
    queryset = ov_scan_result_db.objects.all()
    serializer_class = NetworkScanResultSerializer

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = NetworkScanResultSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get('scan_id',)
            all_scans = ov_scan_result_db.objects.filter(scan_id=scan_id)
            serialized_scans = NetworkScanResultSerializer(all_scans, many=True)
            return Response(serialized_scans.data)