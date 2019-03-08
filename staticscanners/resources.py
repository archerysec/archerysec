from import_export import resources
from staticscanners.models import dependencycheck_scan_results_db, \
    findbugs_scan_results_db, clair_scan_results_db
from compliance.models import inspec_scan_results_db, inspec_scan_db


class DependencyResource(resources.ModelResource):
    class Meta:
        model = dependencycheck_scan_results_db


class FindbugResource(resources.ModelResource):
    class Meta:
        model = findbugs_scan_results_db


class ClairResource(resources.ModelResource):
    class Meta:
        model = clair_scan_results_db


class InspecResource(resources.ModelResource):
    class Meta:
        model = inspec_scan_results_db

