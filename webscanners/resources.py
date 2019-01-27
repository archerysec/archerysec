from import_export import resources
from webscanners.models import zap_scan_results_db, \
    burp_scan_result_db, \
    arachni_scan_result_db, \
    netsparker_scan_result_db, \
    acunetix_scan_result_db, \
    webinspect_scan_result_db

from staticscanners.models import dependencycheck_scan_results_db, findbugs_scan_results_db


class ZapResource(resources.ModelResource):
    class Meta:
        model = zap_scan_results_db


class BurpResource(resources.ModelResource):
    class Meta:
        model = burp_scan_result_db


class ArachniResource(resources.ModelResource):
    class Meta:
        model = arachni_scan_result_db


class NetsparkerResource(resources.ModelResource):
    class Meta:
        model = netsparker_scan_result_db


class AcunetixResource(resources.ModelResource):
    class Meta:
        model = acunetix_scan_result_db


class WebinspectResource(resources.ModelResource):
    class Meta:
        model = webinspect_scan_result_db

class DependencyResource(resources.ModelResource):
    class Meta:
        model = dependencycheck_scan_results_db

class FindbugResource(resources.ModelResource):
    class Meta:
        model = findbugs_scan_results_db


class AllResource(ZapResource,
                  BurpResource,
                  ArachniResource,
                  NetsparkerResource,
                  AcunetixResource,
                  WebinspectResource,
                  DependencyResource,
                  FindbugResource):
    pass
