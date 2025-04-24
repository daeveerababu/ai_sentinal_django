from django.db import models
from django.utils import timezone


class SecurityScan(models.Model):
    """Model for storing security scan information."""
    SCAN_STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    
    SCAN_TYPE_CHOICES = (
        ('spam', 'Spam Detection'),
        ('virus', 'Virus Scan'),
        ('malware', 'Malware Analysis'),
        ('combined', 'Combined Security Check'),
    )
    
    id = models.AutoField(primary_key=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    content = models.TextField(blank=True, null=True, help_text="Text content for spam analysis")
    file_hash = models.CharField(max_length=64, blank=True, null=True, help_text="Hash of the scanned file")
    file_name = models.CharField(max_length=255, blank=True, null=True)
    scan_status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    result_data = models.JSONField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.scan_type} scan - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-created_at']


class SecurityThreat(models.Model):
    """Model for storing detected security threats."""
    THREAT_SEVERITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    
    THREAT_TYPE_CHOICES = (
        ('spam', 'Spam'),
        ('phishing', 'Phishing'),
        ('malware', 'Malware'),
        ('virus', 'Virus'),
        ('ransomware', 'Ransomware'),
        ('other', 'Other'),
    )
    
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(SecurityScan, on_delete=models.CASCADE, related_name='threats')
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPE_CHOICES)
    severity = models.CharField(max_length=10, choices=THREAT_SEVERITY_CHOICES)
    description = models.TextField()
    detection_timestamp = models.DateTimeField(default=timezone.now)
    metadata = models.JSONField(blank=True, null=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.threat_type} - {self.severity} severity ({self.detection_timestamp.strftime('%Y-%m-%d')})"
    
    def resolve(self):
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.save()
    
    class Meta:
        ordering = ['-detection_timestamp']


class SpamClassificationModel(models.Model):
    """Model for managing spam classifier models."""
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
    
    def __str__(self):
        return f"{self.model_name} v{self.model_version}"
    
    class Meta:
        ordering = ['-created_at']
