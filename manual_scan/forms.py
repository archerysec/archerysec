from django import forms
from manual_scan.models import manual_scan_results_db

class ManulScanForm(forms.ModelForm):
    class Meta:
        model = manual_scan_results_db
        fields = ['vuln_name', 'Poc_Img']