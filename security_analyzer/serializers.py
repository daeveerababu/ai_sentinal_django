from rest_framework import serializers
from .models import SecurityScan, SecurityThreat, SpamClassificationModel


class SecurityThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityThreat
        fields = '__all__'


class SecurityScanSerializer(serializers.ModelSerializer):
    threats = SecurityThreatSerializer(many=True, read_only=True)
    
    class Meta:
        model = SecurityScan
        fields = '__all__'


class SpamClassificationModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = SpamClassificationModel
        fields = '__all__'


class TextAnalysisSerializer(serializers.Serializer):
    text = serializers.CharField(required=True)
    analyze_spam = serializers.BooleanField(default=True)
    analyze_sentiment = serializers.BooleanField(default=False)
    
    def validate_text(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Text must be at least 5 characters long")
        return value


class FileAnalysisSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    scan_viruses = serializers.BooleanField(default=True)
    extract_text = serializers.BooleanField(default=False)
    
    def validate_file(self, value):
        if value.size > 50 * 1024 * 1024:  # 50MB max
            raise serializers.ValidationError("File size cannot exceed 50MB")
        return value


class SpamPredictionSerializer(serializers.Serializer):
    text = serializers.CharField(required=True)
    
    def validate_text(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Text must be at least 5 characters long")
        return value
