import os
import json
import uuid
from datetime import datetime
from django.conf import settings

try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False


class SupabaseClient:
    """
    Client for Supabase integration to store and retrieve security scan and prediction data.
    """
    def __init__(self, url=None, key=None):
        self.url = url or settings.SUPABASE_URL
        self.key = key or settings.SUPABASE_API_KEY
        self.connected = False
        if SUPABASE_AVAILABLE and self.url and self.key:
            try:
                self.supabase: Client = create_client(self.url, self.key)
                self.connected = True
            except Exception as e:
                print(f"Supabase connection error: {e}")
        else:
            print("Supabase client not available, running in mock mode")

    def log_scan_result(self, scan_id, scan_type, result):
        """Log a security scan result to Supabase"""
        record = {
            'scan_id': str(scan_id),
            'scan_type': scan_type,
            'timestamp': datetime.utcnow().isoformat(),
            'result': json.dumps(result),
        }
        if not self.connected:
            print(f"[MOCK] log_scan_result: {record}")
            return True
        try:
            resp = self.supabase.table('security_scans') \
                              .insert(record) \
                              .execute()
            if resp.error:
                print(f"Supabase log_scan_result error: {resp.error.message}")
                return False
            return True
        except Exception as e:
            print(f"Exception in log_scan_result: {e}")
            return False

    def log_prediction(self, content, prediction):
        """Log a spam classification prediction to Supabase"""
        record = {
            'id': str(uuid.uuid4()),
            'content_preview': content[:100],
            'timestamp': datetime.utcnow().isoformat(),
            'prediction': json.dumps(prediction),
        }
        if not self.connected:
            print(f"[MOCK] log_prediction: {record}")
            return True
        try:
            resp = self.supabase.table('predictions') \
                              .insert(record) \
                              .execute()
            if resp.error:
                print(f"Supabase log_prediction error: {resp.error.message}")
                return False
            return True
        except Exception as e:
            print(f"Exception in log_prediction: {e}")
            return False

    def get_recent_scans(self, limit=10):
        """Retrieve recent security scans from Supabase"""
        if not self.connected:
            print(f"[MOCK] get_recent_scans limit={limit}")
            return []
        try:
            resp = self.supabase.table('security_scans') \
                              .select('*') \
                              .order('timestamp', desc=True) \
                              .limit(limit) \
                              .execute()
            if resp.error:
                print(f"Supabase get_recent_scans error: {resp.error.message}")
                return []
            return resp.data or []
        except Exception as e:
            print(f"Exception in get_recent_scans: {e}")
            return []

    def get_recent_predictions(self, limit=10):
        """Retrieve recent spam predictions from Supabase"""
        if not self.connected:
            print(f"[MOCK] get_recent_predictions limit={limit}")
            return []
        try:
            resp = self.supabase.table('predictions') \
                              .select('*') \
                              .order('timestamp', desc=True) \
                              .limit(limit) \
                              .execute()
            if resp.error:
                print(f"Supabase get_recent_predictions error: {resp.error.message}")
                return []
            return resp.data or []
        except Exception as e:
            print(f"Exception in get_recent_predictions: {e}")
            return []
