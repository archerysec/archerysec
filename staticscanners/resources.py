from import_export import resources
from staticscanners.models import dependencycheck_scan_results_db, \
    findbugs_scan_results_db


class DependencyResource(resources.ModelResource):
    class Meta:
        model = dependencycheck_scan_results_db


class FindbugResource(resources.ModelResource):
    class Meta:
        model = findbugs_scan_results_db

