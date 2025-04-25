import uuid
import hashlib
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from .models import SecurityScan, SecurityThreat
from .serializers import (
    SecurityScanSerializer,
    SecurityScanRequestSerializer,
    SecurityThreatSerializer,
    SpamPredictionSerializer,
)
from .utils.spam_classifier import SpamDetector
from .utils.virus_scanner import VirusTotalScanner
from .utils.supabase_client import SupabaseClient


class GuestLoginAPIView(APIView):
    """Generate a guest user token for limited scans."""
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        username = f"guest_{uuid.uuid4().hex[:8]}"
        user = User.objects.create_user(username=username)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key})


class SecurityScanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for unified security scans: file, URL, and IP via VirusTotal.
    """
    queryset = SecurityScan.objects.all()
    serializer_class = SecurityScanSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'], parser_classes=[MultiPartParser])
    def scan(self, request):
        """
        Unified scan endpoint: accepts file, url, and/or ip.
        """
        serializer = SecurityScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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

            # Update scan record
            scan.result_data = result
            scan.scan_status = 'completed'
            scan.updated_at = timezone.now()
            scan.save()

            # Log to Supabase
            SupabaseClient().log_scan_result(scan_id=scan.id, scan_type=scan_type, result=result)

            return Response(SecurityScanSerializer(scan).data)
        except Exception as e:
            scan.scan_status = 'failed'
            scan.result_data = {'error': str(e)}
            scan.updated_at = timezone.now()
            scan.save()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileScanAPIView(APIView):
    """Endpoint to upload and scan a file via VirusTotal."""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({'detail': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).scan_file(file_obj)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileInfoAPIView(APIView):
    """Endpoint to fetch file report by SHA-256 hash."""
    permission_classes = [IsAuthenticated]

    def get(self, request, file_hash):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).get_file_report(file_hash)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileRescanAPIView(APIView):
    """Endpoint to rescan an existing file by SHA-256."""
    permission_classes = [IsAuthenticated]

    def post(self, request, file_hash):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).rescan_file(file_hash)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UrlAnalyzeAPIView(APIView):
    """Endpoint to submit and analyze a URL via VirusTotal."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        url = request.data.get('url')
        if not url:
            return Response({'detail': 'No URL provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).scan_url(url)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UrlRescanAPIView(APIView):
    """Endpoint to rescan a URL by analysis ID."""
    permission_classes = [IsAuthenticated]

    def post(self, request, url_id):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).rescan_url(url_id)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DomainInfoAPIView(APIView):
    """Endpoint to fetch domain info via VirusTotal."""
    permission_classes = [IsAuthenticated]

    def get(self, request, domain):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).scan_domain(domain)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class IpInfoAPIView(APIView):
    """Endpoint to fetch IP address info via VirusTotal."""
    permission_classes = [IsAuthenticated]

    def get(self, request, ip_address):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).scan_ip(ip_address)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class IpRescanAPIView(APIView):
    """Endpoint to rescan an IP address via VirusTotal."""
    permission_classes = [IsAuthenticated]

    def post(self, request, ip_address):
        try:
            result = VirusTotalScanner(api_key=settings.VIRUS_TOTAL_API_KEY).rescan_ip(ip_address)
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SpamDetectionAPIView(APIView):
    """Endpoint for ML-based spam/ham classification."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SpamPredictionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        text = serializer.validated_data['text']
        try:
            detector = SpamDetector()
            result = detector.predict(text)

            # Log to Supabase
            SupabaseClient().log_prediction(content=text[:500], prediction=result)

            return Response({
                'is_spam': result.get('is_spam'),
                'confidence': result.get('confidence'),
                'spam_score': result.get('spam_score'),
                'ham_score': result.get('ham_score'),
            })
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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