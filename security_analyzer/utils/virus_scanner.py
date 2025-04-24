import os
import requests
import time
from django.conf import settings
import hashlib

class VirusTotalScanner:
    """
    Interface for the VirusTotal API to scan files, URLs, and IPs for threats
    """
    def __init__(self, api_key=None):
        self.api_key = api_key or settings.VIRUS_TOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _get_file_hash(self, file_obj):
        """Calculate SHA-256 hash of an uploaded file"""
        hasher = hashlib.sha256()
        file_obj.seek(0)
        for chunk in file_obj.chunks():
            hasher.update(chunk)
        file_obj.seek(0)
        return hasher.hexdigest()

    def scan_file(self, file_obj):
        """Upload and scan a file via VirusTotal, returning the analysis report"""
        # compute hash and submit
        file_hash = self._get_file_hash(file_obj)
        files = {"file": (file_obj.name, file_obj, "application/octet-stream")}
        submit = requests.post(
            f"{self.base_url}/files",
            headers={**self.headers, "Content-Type": None},
            files=files
        )
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        # poll until done
        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        while True:
            resp = requests.get(analysis_url, headers=self.headers)
            resp.raise_for_status()
            status = resp.json()["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(1)

        # fetch final report
        report = requests.get(f"{self.base_url}/files/{file_hash}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def scan_url(self, url: str):
        """Submit and scan a URL via VirusTotal, returning the analysis report"""
        submit = requests.post(
            f"{self.base_url}/urls",
            headers=self.headers,
            data={"url": url}
        )
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        while True:
            resp = requests.get(analysis_url, headers=self.headers)
            resp.raise_for_status()
            status = resp.json()["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(1)

        report = requests.get(f"{self.base_url}/urls/{url}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def scan_ip(self, ip_address: str):
        """Query and retrieve an IP address report via VirusTotal"""
        resp = requests.get(
            f"{self.base_url}/ip_addresses/{ip_address}",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def get_file_report(self, file_hash: str):
        """Retrieve a past file report by SHA-256 hash"""
        resp = requests.get(f"{self.base_url}/files/{file_hash}", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]
