import hashlib
from django.conf import settings
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from .models import SecurityScan, SecurityThreat
from .serializers import (
    SecurityScanSerializer,
    SecurityScanRequestSerializer,
    SecurityThreatSerializer,
    SpamPredictionSerializer
)
from .utils.spam_classifier import SpamDetector
from .utils.virus_scanner import VirusTotalScanner
from .utils.supabase_client import SupabaseClient


class SecurityScanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for security scans: file, URL, and IP via VirusTotal.
    """
    queryset = SecurityScan.objects.all()
    serializer_class = SecurityScanSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'])
    def scan(self, request):
        """
        Unified scan endpoint: accepts file, url, and/or ip.
        """
        serializer = SecurityScanRequestSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            vt = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY)

            # Determine scan_type
            types = []
            if data.get('file'):
                types.append('virus')
            if data.get('url'):
                types.append('url')
            if data.get('ip'):
                types.append('ip')
            scan_type = 'combined' if len(types) > 1 else types[0]

            # Create scan record
            scan = SecurityScan.objects.create(
                scan_type=scan_type,
                content=data.get('url') or data.get('ip'),
                file_hash=None,
                file_name=data.get('file').name if data.get('file') else None,
                scan_status='processing',
                created_at=timezone.now(),
            )

            try:
                result = {}
                # File scan
                if data.get('file'):
                    file_result = vt.scan_file(data['file'])
                    result['file'] = file_result
                    scan.file_hash = file_result.get('sha256')
                # URL scan
                if data.get('url'):
                    result['url'] = vt.scan_url(data['url'])
                # IP scan
                if data.get('ip'):
                    result['ip'] = vt.scan_ip(data['ip'])

                # Update and save scan
                scan.result_data = result
                scan.scan_status = 'completed'
                scan.updated_at = timezone.now()
                scan.save()

                # Log to Supabase
                supabase = SupabaseClient()
                supabase.log_scan_result(scan_id=scan.id, scan_type=scan_type, result=result)

                return Response(SecurityScanSerializer(scan).data)
            except Exception as e:
                scan.scan_status = 'failed'
                scan.result_data = {'error': str(e)}
                scan.updated_at = timezone.now()
                scan.save()
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SpamDetectionAPIView(APIView):
    """
    API for spam detection using ML model.
    """
    def post(self, request):
        serializer = SpamPredictionSerializer(data=request.data)
        if serializer.is_valid():
            text = serializer.validated_data['text']
            try:
                detector = SpamDetector()
                result = detector.predict(text)

                # Log to Supabase
                supabase = SupabaseClient()
                supabase.log_prediction(content=text[:500], prediction=result)

                return Response({
                    'is_spam': result.get('is_spam', False),
                    'confidence': result.get('confidence', 0),
                    'prediction': 'spam' if result.get('is_spam') else 'ham'
                })
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SecurityThreatViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing security threats detected in scans.
    """
    queryset = SecurityThreat.objects.all()
    serializer_class = SecurityThreatSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        threat = self.get_object()
        threat.resolve()
        return Response({'status': 'resolved'})

    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        qs = SecurityThreat.objects.filter(is_resolved=False)
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)
