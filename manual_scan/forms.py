from django import forms

from manual_scan.models import ManualScanResultsDb


class ManulScanForm(forms.ModelForm):
    class Meta:
        model = ManualScanResultsDb
        fields = ["vuln_name", "Poc_Img"]
