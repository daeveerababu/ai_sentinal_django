import os
import json
import uuid
import time
from datetime import datetime
from django.conf import settings

try:
    # Use actual Supabase client if available
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    # Mock for development without actual Supabase dependency
    SUPABASE_AVAILABLE = False


class SupabaseClient:
    """
    Client for Supabase integration to store security data
    """
    def __init__(self, url=None, key=None):
        self.url = url or settings.SUPABASE_URL
        self.key = key or settings.SUPABASE_KEY
        
        # Initialize Supabase client if available
        if SUPABASE_AVAILABLE and self.url and self.key:
            try:
                self.supabase: Client = create_client(self.url, self.key)
                self.connected = True
                print("Connected to Supabase")
            except Exception as e:
                print(f"Error connecting to Supabase: {str(e)}")
                self.connected = False
        else:
            print("Supabase client not available - using mock implementation")
            self.connected = False
    
    def log_scan_result(self, scan_id, scan_type, result):
        """Log a security scan result to Supabase"""
        if not self.connected:
            # Mock implementation for development
            print(f"[MOCK] Logging scan result to Supabase: scan_id={scan_id}, type={scan_type}")
            return True
        
        try:
            # Add scan record to Supabase
            data = {
                'scan_id': str(scan_id),
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'result': json.dumps(result) if isinstance(result, dict) else str(result)
            }
            
            response = self.supabase.table('security_scans').insert(data).execute()
            
            if hasattr(response, 'error') and response.error:
                print(f"Error logging to Supabase: {response.error.message}")
                return False
            
            return True
        
        except Exception as e:
            print(f"Exception logging to Supabase: {str(e)}")
            return False
    
    def log_prediction(self, content, prediction):
        """Log a prediction result to Supabase"""
        if not self.connected:
            # Mock implementation for development
            print(f"[MOCK] Logging prediction to Supabase: content={content[:20]}..., prediction={prediction}")
            return True
        
        try:
            # Add prediction record to Supabase
            data = {
                'id': str(uuid.uuid4()),
                'content_preview': content[:100] if content else '',
                'timestamp': datetime.now().isoformat(),
                'prediction': json.dumps(prediction) if isinstance(prediction, dict) else str(prediction)
            }
            
            response = self.supabase.table('predictions').insert(data).execute()
            
            if hasattr(response, 'error') and response.error:
                print(f"Error logging prediction to Supabase: {response.error.message}")
                return False
            
            return True
        
        except Exception as e:
            print(f"Exception logging prediction to Supabase: {str(e)}")
            return False
    
    def get_recent_scans(self, limit=10):
        """Get recent security scans from Supabase"""
        if not self.connected:
            # Mock implementation for development
            print(f"[MOCK] Getting recent scans from Supabase: limit={limit}")
            return [
                {
                    'id': f'scan-{i}',
                    'scan_type': 'spam' if i % 2 == 0 else 'virus',
                    'timestamp
