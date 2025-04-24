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


class SecurityScanRequestSerializer(serializers.Serializer):
    """
    Serializer for incoming security scan requests. Requires at least one of file, url, or ip.
    """
    file = serializers.FileField(required=False)
    url = serializers.URLField(required=False)
    ip = serializers.IPAddressField(required=False)

    def validate(self, data):
        if not (data.get('file') or data.get('url') or data.get('ip')):
            raise serializers.ValidationError(
                "Provide at least one of 'file', 'url', or 'ip' to scan."
            )
        return data


class SpamPredictionSerializer(serializers.Serializer):
    text = serializers.CharField(required=True)

    def validate_text(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Text must be at least 5 characters long")
        return value


class TextAnalysisSerializer(serializers.Serializer):
    text = serializers.CharField(required=True)
    analyze_spam = serializers.BooleanField(default=True)
    analyze_sentiment = serializers.BooleanField(default=False)

    def validate_text(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Text must be at least 5 characters long")
        return value
