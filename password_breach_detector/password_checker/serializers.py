from rest_framework import serializers
from .models import PasswordCheck, PasswordStrengthAnalysis

class PasswordCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordCheck
        fields = [
            'id', 'hash_prefix', 'sha256_hash', 'check_timestamp', 
            'was_breached', 'breach_count', 'breach_details', 
            'strength_score', 'entropy', 'crack_time', 'recommendation'
        ]
        read_only_fields = ['id', 'sha256_hash', 'check_timestamp', 'was_breached', 'breach_count', 'breach_details']

class PasswordStrengthAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordStrengthAnalysis
        fields = [
            'id', 'hash_prefix', 'strength_score', 'entropy', 
            'crack_time', 'analysis_timestamp', 'recommendations'
        ]
        read_only_fields = ['id', 'analysis_timestamp']
