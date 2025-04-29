from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from .models import PasswordCheck, PasswordStrengthAnalysis
from .serializers import PasswordCheckSerializer, PasswordStrengthAnalysisSerializer
from .api_client import HaveIBeenPwnedClient
from .tasks import send_breach_notification
import hashlib

class PasswordCheckThrottle(UserRateThrottle):
    """Throttle for password check requests"""
    scope = 'password_check'

class PasswordCheckViewSet(viewsets.ModelViewSet):
    """Handle password checking against breach database"""
    queryset = PasswordCheck.objects.all()
    serializer_class = PasswordCheckSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [PasswordCheckThrottle]
    
    def get_queryset(self):
        """Filter queryset to only show user's own checks"""
        return PasswordCheck.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['post'])
    def check_password(self, request):
        """
        Check if a password has been breached
        
        Request data:
            hash_prefix: First 5 characters of SHA-1 hash
            hash_suffix: Remaining characters of SHA-1 hash (frontend computes this)
        """
        hash_prefix = request.data.get('hash_prefix')
        hash_suffix = request.data.get('hash_suffix')
        
        if not hash_prefix or not hash_suffix:
            return Response(
                {'error': 'Both hash_prefix and hash_suffix are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate hash format
        if len(hash_prefix) != 5 or not all(c in '0123456789ABCDEF' for c in hash_prefix):
            return Response(
                {'error': 'Invalid hash_prefix format'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if len(hash_suffix) != 35 or not all(c in '0123456789ABCDEF' for c in hash_suffix):
            return Response(
                {'error': 'Invalid hash_suffix format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        api_client = HaveIBeenPwnedClient()
        
        # Query the API with just the prefix
        headers = {
            'User-Agent': 'PasswordBreachDetector/1.0',
            'hibp-api-key': api_client.api_key
        }
        response = requests.get(
            f"{api_client.API_BASE_URL}/range/{hash_prefix}",
            headers=headers
        )
        
        if response.status_code != 200:
            return Response(
                {'error': 'Error connecting to breach database'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        
        # Parse the response to find any matches
        breach_count = 0
        breach_found = False
        
        for line in response.text.splitlines():
            line_suffix, count = line.split(":")
            if line_suffix == hash_suffix:
                breach_count = int(count)
                breach_found = True
                break
        
        # Store the check result
        check = PasswordCheck.objects.create(
            user=request.user,
            hash_prefix=hash_prefix,
            was_breached=breach_found,
            breach_count=breach_count
        )
        
        # If breach found, send notification asynchronously
        if breach_found and request.user.receive_breach_notifications:
            send_breach_notification.delay(check.id)
        
        return Response({
            'was_breached': breach_found,
            'breach_count': breach_count,
            'check_id': check.id
        })
    
    @action(detail=False, methods=['post'])
    def analyze_strength(self, request):
        """
        Analyze password strength
        
        Request data:
            hash_prefix: First 5 characters of SHA-1 hash
            length: Password length
            has_uppercase: Boolean
            has_lowercase: Boolean
            has_numbers: Boolean
            has_symbols: Boolean
        """
        hash_prefix = request.data.get('hash_prefix')
        length = request.data.get('length', 0)
        has_uppercase = request.data.get('has_uppercase', False)
        has_lowercase = request.data.get('has_lowercase', False)
        has_numbers = request.data.get('has_numbers', False)
        has_symbols = request.data.get('has_symbols', False)
        
        if not hash_prefix:
            return Response(
                {'error': 'hash_prefix is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate strength score (0.0 to 1.0)
        score = 0.0
        
        # Length contributes up to 0.4 of score
        length_score = min(length / 20, 1.0) * 0.4
        
        # Character types contribute up to 0.4 of score
        charset_score = 0.0
        if has_lowercase:
            charset_score += 0.1
        if has_uppercase:
            charset_score += 0.1
        if has_numbers:
            charset_score += 0.1
        if has_symbols:
            charset_score += 0.1
        
        # Combine scores
        score = length_score + charset_score
        
        # Generate recommendations
        recommendations = []
        
        if length < 12:
            recommendations.append("Use at least 12 characters")
        if not has_uppercase:
            recommendations.append("Add uppercase letters")
        if not has_lowercase:
            recommendations.append("Add lowercase letters")
        if not has_numbers:
            recommendations.append("Add numbers")
        if not has_symbols:
            recommendations.append("Add special characters")
        
        # Store the analysis
        analysis = PasswordStrengthAnalysis.objects.create(
            user=request.user,
            hash_prefix=hash_prefix,
            strength_score=score,
            recommendations=recommendations
        )
        
        return Response({
            'strength_score': score,
            'recommendations': recommendations,
            'analysis_id': analysis.id
        })
