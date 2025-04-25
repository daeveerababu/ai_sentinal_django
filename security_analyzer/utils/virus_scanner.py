import time
import hashlib
import requests
from django.conf import settings


class VirusTotalScanner:
    """
    Interface for the VirusTotal API v3 to scan and rescan files, URLs, domains, and IPs.
    """
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key=None):
        self.api_key = api_key or settings.VIRUS_TOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _get_file_hash(self, file_obj):
        """Calculate SHA-256 hash of the file."""
        hasher = hashlib.sha256()
        file_obj.seek(0)
        for chunk in file_obj.chunks():
            hasher.update(chunk)
        file_obj.seek(0)
        return hasher.hexdigest()

    def _poll_analysis(self, analysis_id, timeout=30):
        """Poll analysis until completed or timeout."""
        analysis_url = f"{self.BASE_URL}/analyses/{analysis_id}"
        for _ in range(timeout):
            resp = requests.get(analysis_url, headers=self.headers)
            if resp.status_code == 429:  # Rate limited
                time.sleep(5)
                continue
            status = resp.json()["data"]["attributes"]["status"]
            if status == "completed":
                return True
            time.sleep(1)
        raise TimeoutError("Analysis polling timed out.")

    def scan_file(self, file_obj):
        """Upload a file for scanning and retrieve its results."""
        file_hash = self._get_file_hash(file_obj)
        files = {"file": (file_obj.name, file_obj, "application/octet-stream")}
        resp = requests.post(f"{self.BASE_URL}/files", headers=self.headers, files=files)
        resp.raise_for_status()

        analysis_id = resp.json()["data"]["id"]
        self._poll_analysis(analysis_id)

        report = requests.get(f"{self.BASE_URL}/files/{file_hash}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def get_file_report(self, file_hash: str):
        """Fetch a report by SHA-256 hash of a previously scanned file."""
        resp = requests.get(f"{self.BASE_URL}/files/{file_hash}", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def rescan_file(self, file_hash: str):
        """Trigger a rescan of a previously submitted file."""
        resp = requests.post(f"{self.BASE_URL}/files/{file_hash}/analyse", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["data"]["id"]

    def scan_url(self, url: str):
        """Scan a URL and retrieve its threat report."""
        submit_resp = requests.post(f"{self.BASE_URL}/urls", headers=self.headers, data={"url": url})
        submit_resp.raise_for_status()

        analysis_id = submit_resp.json()["data"]["id"]
        self._poll_analysis(analysis_id)

        report = requests.get(f"{self.BASE_URL}/urls/{analysis_id}", headers=self.headers)
        report.raise_for_status()
        return report.json()["data"]["attributes"]

    def rescan_url(self, url: str):
        """Re-scan a URL by resubmitting it (VT v3 rescan is re-submission)."""
        return self.scan_url(url)

    def scan_domain(self, domain: str):
        """Get a threat profile for a domain."""
        resp = requests.get(f"{self.BASE_URL}/domains/{domain}", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def scan_ip(self, ip_address: str):
        """Get a threat profile for an IP address."""
        resp = requests.get(f"{self.BASE_URL}/ip_addresses/{ip_address}", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["data"]["attributes"]

    def rescan_ip(self, ip_address: str):
        """Rescan is not supported for IPs in VT v3; fetch again for latest info."""
        return self.scan_ip(ip_address)
