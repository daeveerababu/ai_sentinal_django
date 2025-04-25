from django.db import models
from django.utils import timezone


class SecurityScan(models.Model):
    """
    Represents a security scan initiated by the system.
    Includes scan types like spam, malware, URL, IP, or combined checks.
    """
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    SCAN_TYPE_CHOICES = [
        ('spam', 'Spam Detection'),
        ('virus', 'File/Malware Scan'),
        ('url', 'URL Analysis'),
        ('ip', 'IP Address Analysis'),
        ('combined', 'Combined Security Check'),
    ]

    id = models.AutoField(primary_key=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    content = models.TextField(blank=True, null=True, help_text="Message, URL, or IP address")
    file_hash = models.CharField(max_length=64, blank=True, null=True, help_text="SHA-256 hash")
    file_name = models.CharField(max_length=255, blank=True, null=True)
    scan_status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    result_data = models.JSONField(blank=True, null=True, help_text="API scan results")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_scan_type_display()} scan on {self.created_at:%Y-%m-%d %H:%M}"


class SecurityThreat(models.Model):
    """
    Represents a threat detected from a security scan.
    Includes severity and resolution tracking.
    """
    THREAT_SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    THREAT_TYPE_CHOICES = [
        ('spam', 'Spam'),
        ('phishing', 'Phishing'),
        ('malware', 'Malware'),
        ('virus', 'Virus'),
        ('ransomware', 'Ransomware'),
        ('other', 'Other'),
    ]

    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(SecurityScan, on_delete=models.CASCADE, related_name='threats')
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPE_CHOICES)
    severity = models.CharField(max_length=10, choices=THREAT_SEVERITY_CHOICES)
    description = models.TextField()
    metadata = models.JSONField(blank=True, null=True)
    detection_timestamp = models.DateTimeField(default=timezone.now)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ['-detection_timestamp']

    def resolve(self):
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.save()

    def __str__(self):
        return f"{self.get_threat_type_display()} ({self.get_severity_display()}) at {self.detection_timestamp:%Y-%m-%d %H:%M}"


class SpamClassificationModel(models.Model):
    """
    Stores metadata and artifacts related to trained spam detection models.
    Includes versioning, evaluation metrics, and active model flag.
    """
    model_name = models.CharField(max_length=100)
    model_version = models.CharField(max_length=50)
    created_at = models.DateTimeField(default=timezone.now)
    model_file = models.FileField(upload_to='ml_models/')
    feature_extraction_file = models.FileField(upload_to='ml_models/', blank=True, null=True)
    accuracy = models.FloatField(default=0.0)
    precision = models.FloatField(default=0.0)
    recall = models.FloatField(default=0.0)
    f1_score = models.FloatField(default=0.0)
    is_active = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.model_name} v{self.model_version}"
