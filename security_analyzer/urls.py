from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SecurityScanViewSet,
    SecurityThreatViewSet,
    SpamDetectionAPIView,
    FileScanAPIView,
    FileInfoAPIView,
    FileRescanAPIView,
    UrlAnalyzeAPIView,
    UrlRescanAPIView,
    DomainInfoAPIView,
    IpInfoAPIView,
    IpRescanAPIView,
)

router = DefaultRouter()
router.register(r'scans', SecurityScanViewSet, basename='security-scan')
router.register(r'threats', SecurityThreatViewSet, basename='security-threat')

urlpatterns = [
    # Core ViewSet routes
    # Authentication
    path('guest-login/', GuestLoginAPIView.as_view(), name='guest-login'),
    
    path('', include(router.urls)),

    # Spam detection (ML)
    path('spam/', SpamDetectionAPIView.as_view(), name='spam-detect'),

    # File endpoints
    path('files/scan/',    FileScanAPIView.as_view(), name='file-scan'),      # POST file upload
    path('files/info/<str:file_hash>/', FileInfoAPIView.as_view(), name='file-info'),  # GET info by SHA256
    path('files/rescan/<str:file_hash>/', FileRescanAPIView.as_view(), name='file-rescan'),

    # URL endpoints
    path('urls/analyze/',  UrlAnalyzeAPIView.as_view(), name='url-analyze'),  # POST with URL
    path('urls/rescan/<str:url_id>/', UrlRescanAPIView.as_view(), name='url-rescan'),

    # Domain info
    path('domains/info/<str:domain>/', DomainInfoAPIView.as_view(), name='domain-info'),

    # IP endpoints
    path('ip_addresses/info/<str:ip_address>/', IpInfoAPIView.as_view(), name='ip-info'),
    path('ip_addresses/rescan/<str:ip_address>/', IpRescanAPIView.as_view(), name='ip-rescan'),
]
