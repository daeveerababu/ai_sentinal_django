import os
import json
import hashlib
from django.conf import settings
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from .models import SecurityScan, SecurityThreat, SpamClassificationModel
from .serializers import (
    SecurityScanSerializer, 
    SecurityThreatSerializer,
    SpamClassificationModelSerializer,
    TextAnalysisSerializer,
    FileAnalysisSerializer,
    SpamPredictionSerializer
)
from .utils.spam_classifier import SpamDetector
from .utils.virus_scanner import VirusTotalScanner
from .utils.supabase_client import SupabaseClient


class SecurityScanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for security scans management
    """
    queryset = SecurityScan.objects.all()
    serializer_class = SecurityScanSerializer
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def scan_text(self, request):
        """Analyze text for spam/threats"""
        serializer = TextAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            text = serializer.validated_data['text']
            analyze_spam = serializer.validated_data['analyze_spam']
            
            # Create a scan record
            scan = SecurityScan.objects.create(
                scan_type='spam',
                content=text,
                scan_status='processing'
            )
            
            try:
                # Perform spam detection
                if analyze_spam:
                    spam_detector = SpamDetector()
                    result = spam_detector.predict(text)
                    
                    # Update scan record
                    scan.result_data = result
                    scan.scan_status = 'completed'
                    scan.save()
                    
                    # Create threat if spam detected
                    if result.get('is_spam', False):
                        SecurityThreat.objects.create(
                            scan=scan,
                            threat_type='spam',
                            severity='medium',
                            description=f"Spam detected with {result.get('confidence', 0)*100:.1f}% confidence",
                            metadata={'prediction_details': result}
                        )
                        
                    # Log to Supabase
                    supabase_client = SupabaseClient()
                    supabase_client.log_scan_result(scan_id=scan.id, scan_type='spam', result=result)
                    
                return Response(SecurityScanSerializer(scan).data)
                
            except Exception as e:
                scan.scan_status = 'failed'
                scan.result_data = {'error': str(e)}
                scan.save()
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def scan_file(self, request):
        """Scan file for viruses/malware"""
        serializer = FileAnalysisSerializer(data=request.data)
        if serializer.is_valid():
            file_obj = serializer.validated_data['file']
            scan_viruses = serializer.validated_data['scan_viruses']
            
            # Calculate file hash
            hasher = hashlib.sha256()
            for chunk in file_obj.chunks():
                hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            # Create a scan record
            scan = SecurityScan.objects.create(
                scan_type='virus',
                file_name=file_obj.name,
                file_hash=file_hash,
                scan_status='processing'
            )
            
            try:
                # Virus scan
                if scan_viruses:
                    scanner = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY)
                    scan_result = scanner.scan_file(file_obj)
                    
                    # Update scan record
                    scan.result_data = scan_result
                    scan.scan_status = 'completed'
                    scan.save()
                    
                    # Create threat records if threats detected
                    if scan_result.get('positives', 0) > 0:
                        SecurityThreat.objects.create(
                            scan=scan,
                            threat_type='virus',
                            severity='high' if scan_result.get('positives', 0) > 5 else 'medium',
                            description=f"Detected by {scan_result.get('positives', 0)} engines",
                            metadata={'scan_details': scan_result}
                        )
                    
                    # Log to Supabase
                    supabase_client = SupabaseClient()
                    supabase_client.log_scan_result(scan_id=scan.id, scan_type='virus', result=scan_result)
                    
                return Response(SecurityScanSerializer(scan).data)
                
            except Exception as e:
                scan.scan_status = 'failed'
                scan.result_data = {'error': str(e)}
                scan.save()
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SpamDetectionAPIView(APIView):
    """
    API for spam detection
    """
    def post(self, request):
        serializer = SpamPredictionSerializer(data=request.data)
        if serializer.is_valid():
            text = serializer.validated_data['text']
            
            try:
                # Get prediction
                spam_detector = SpamDetector()
                result = spam_detector.predict(text)
                
                # Log the prediction to Supabase
                supabase_client = SupabaseClient()
                supabase_client.log_prediction(content=text[:500], prediction=result)
                
                return Response({
                    'is_spam': result.get('is_spam', False),
                    'confidence': result.get('confidence', 0),
                    'prediction': 'spam' if result.get('is_spam', False) else 'ham'
                })
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SecurityThreatViewSet(viewsets.ModelViewSet):
    """
    API endpoint for security threats management
    """
    queryset = SecurityThreat.objects.all()
    serializer_class = SecurityThreatSerializer
    permission_classes = [IsAuthenticated]
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        threat = self.get_object()
        threat.resolve()
        return Response({'status': 'threat resolved'})
    
    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        threats = SecurityThreat.objects.filter(is_resolved=False)
        serializer = self.get_serializer(threats, many=True)
        return Response(serializer.data)
