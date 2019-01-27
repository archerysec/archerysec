from import_export import resources
from networkscanners.models import ov_scan_result_db,\
    nessus_report_db


class OpenvasResource(resources.ModelResource):
    class Meta:
        model = ov_scan_result_db


class NessusResource(resources.ModelResource):
    class Meta:
        model = nessus_report_db

