import os
import time
import requests
from django.conf import settings
import hashlib

class VirusTotalScanner:
    """
    Interface for the VirusTotal API v3 to scan and rescan files, URLs, domains, and IPs.
    """
    def __init__(self, api_key=None):
        self.api_key = api_key or settings.VIRUS_TOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _get_file_hash(self, file_obj):
        """Calculate SHA-256 hash of an uploaded file."""
        hasher = hashlib.sha256()
        file_obj.seek(0)
        for chunk in file_obj.chunks():
            hasher.update(chunk)
        file_obj.seek(0)
        return hasher.hexdigest()

    def scan_file(self, file_obj):
        """Upload a file for scanning, then fetch its report."""
        # 1) Submit file
        file_hash = self._get_file_hash(file_obj)
        files = {"file": (file_obj.name, file_obj, "application/octet-stream")}
        resp = requests.post(
            f"{self.base_url}/files",
            headers={**self.headers, "Content-Type": None},
            files=files
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        # 2) Poll analysis status
        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        while True:
            status = requests.get(analysis_url, headers=self.headers).json()\
                        ["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(1)

        # 3) Fetch final report
        report = requests.get(f"{self.base_url}/files/{file_hash}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def rescan_file(self, file_hash: str):
        """Re-submit an existing file (by SHA-256) for fresh analysis."""
        resp = requests.post(
            f"{self.base_url}/files/{file_hash}/rescan",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def scan_url(self, url: str):
        """Submit a URL for scanning, then fetch its report."""
        resp = requests.post(
            f"{self.base_url}/urls",
            headers=self.headers,
            data={"url": url}
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        while True:
            status = requests.get(analysis_url, headers=self.headers).json()\
                        ["data"]["attributes"]["status"]
            if status == "completed":
                break
            time.sleep(1)

        # Note: VT returns a URL-safe ID; you can also fetch by that ID instead of raw URL
        report = requests.get(f"{self.base_url}/urls/{analysis_id}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def rescan_url(self, url_id: str):
        """Re-submit an existing URL analysis ID for fresh scanning."""
        resp = requests.post(
            f"{self.base_url}/urls/{url_id}/rescan",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def scan_domain(self, domain: str):
        """Fetch threat reputation for a domain."""
        resp = requests.get(
            f"{self.base_url}/domains/{domain}",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def scan_ip(self, ip_address: str):
        """Fetch threat reputation for an IP address."""
        resp = requests.get(
            f"{self.base_url}/ip_addresses/{ip_address}",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def rescan_ip(self, ip_address: str):
        """Re-submit an existing IP for fresh analysis."""
        resp = requests.post(
            f"{self.base_url}/ip_addresses/{ip_address}/rescan",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def get_file_report(self, file_hash: str):
        """Alias for fetching a past file report by SHA-256."""
        return self.scan_file  # same as scan_file for VT-v3
