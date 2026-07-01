import hashlib
import requests
import logging
from django.conf import settings
from django.db.models import Count
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

from .models import PasswordCheck, PasswordStrengthAnalysis
from .serializers import PasswordCheckSerializer, PasswordStrengthAnalysisSerializer
from .api_client import HaveIBeenPwnedClient
from .entropy import (
    calculate_entropy, 
    estimate_crack_times, 
    check_dictionary_words,
    check_sequential_patterns,
    check_keyboard_patterns,
    check_repeated_characters
)
from breach_analyzer.tasks import send_breach_notification
from users.models import ActivityLog

logger = logging.getLogger(__name__)

# Password Strength Analyzer raw helper
def analyze_password_strength_raw(password):
    if not password:
        return 0.0, 0.0, "instant", ["Password is empty"]
    
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Base length score (max 0.4)
    if length < 8:
        length_score = 0.0
    elif length < 12:
        length_score = 0.2
    elif length < 16:
        length_score = 0.3
    else:
        length_score = 0.4
        
    # Complexity score (max 0.6)
    complexity_score = 0.0
    if has_lower:
        complexity_score += 0.15
    if has_upper:
        complexity_score += 0.15
    if has_digit:
        complexity_score += 0.15
    if has_special:
        complexity_score += 0.15
        
    score = length_score + complexity_score
    
    recommendations = []
    if length < 12:
        recommendations.append("Use a longer password (at least 12 characters)")
    if not has_upper:
        recommendations.append("Add uppercase letters")
    if not has_lower:
        recommendations.append("Add lowercase letters")
    if not has_digit:
        recommendations.append("Add numbers")
    if not has_special:
        recommendations.append("Add special characters/symbols")
        
    # Entropy calculation
    entropy, pool_size = calculate_entropy(password)
    crack_times = estimate_crack_times(entropy)
    gpu_time = crack_times["gpu"]
    
    # Pattern penalties
    has_dict, word = check_dictionary_words(password)
    if has_dict:
        score -= 0.2
        recommendations.append(f"Avoid common dictionary words or names (found: '{word}')")
        
    has_seq, seq = check_sequential_patterns(password)
    if has_seq:
        score -= 0.15
        recommendations.append(f"Avoid sequential character patterns (found: '{seq}')")
        
    has_kb, kb = check_keyboard_patterns(password)
    if has_kb:
        score -= 0.15
        recommendations.append(f"Avoid simple keyboard patterns (found: '{kb}')")
        
    has_rep, rep = check_repeated_characters(password)
    if has_rep:
        score -= 0.15
        recommendations.append(f"Avoid repeated consecutive characters (found: '{rep}')")
        
    score = max(0.0, min(1.0, score))
    return score, entropy, gpu_time, recommendations

# Password Generator helper
def generate_secure_password(length=12, uppercase=True, lowercase=True, numbers=True, symbols=True, exclude_similar=False):
    import random
    import string
    
    similar_chars = "ilI1o0O9gq8BDS5S2Z"
    
    upper_pool = string.ascii_uppercase
    lower_pool = string.ascii_lowercase
    digit_pool = string.digits
    symbol_pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if exclude_similar:
        upper_pool = "".join(c for c in upper_pool if c not in similar_chars)
        lower_pool = "".join(c for c in lower_pool if c not in similar_chars)
        digit_pool = "".join(c for c in digit_pool if c not in similar_chars)
        symbol_pool = "".join(c for c in symbol_pool if c not in similar_chars)
        
    chars = ""
    if uppercase:
        chars += upper_pool
    if lowercase:
        chars += lower_pool
    if numbers:
        chars += digit_pool
    if symbols:
        chars += symbol_pool
        
    if not chars:
        chars = string.ascii_letters + string.digits
        
    password_list = []
    if uppercase and upper_pool:
        password_list.append(random.choice(upper_pool))
    if lowercase and lower_pool:
        password_list.append(random.choice(lower_pool))
    if numbers and digit_pool:
        password_list.append(random.choice(digit_pool))
    if symbols and symbol_pool:
        password_list.append(random.choice(symbol_pool))
        
    remaining = length - len(password_list)
    if remaining > 0:
        password_list.extend(random.choice(chars) for _ in range(remaining))
        
    random.shuffle(password_list)
    return "".join(password_list)

class PasswordCheckThrottle(UserRateThrottle):
    scope = 'password_check'

class PasswordCheckViewSet(viewsets.ModelViewSet):
    """Handle password checking against breach database"""
    queryset = PasswordCheck.objects.all()
    serializer_class = PasswordCheckSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [PasswordCheckThrottle]
    
    def get_queryset(self):
        return PasswordCheck.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['post'], url_path='check')
    def check_password(self, request):
        """
        Check if a password has been breached (compatible with frontend password-check.js)
        """
        hash_prefix = request.data.get('hash_prefix')
        hash_suffix = request.data.get('hash_suffix')
        
        if not hash_prefix or not hash_suffix:
            return Response(
                {'error': 'Both hash_prefix and hash_suffix are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        hash_prefix = hash_prefix.upper()
        hash_suffix = hash_suffix.upper()
        
        # Query HaveIBeenPwned
        api_client = HaveIBeenPwnedClient()
        try:
            headers = {
                'User-Agent': 'PasswordBreachDetector/1.0',
            }
            if api_client.api_key:
                headers['hibp-api-key'] = api_client.api_key
                
            response = requests.get(
                f"{api_client.API_BASE_URL}/range/{hash_prefix}",
                headers=headers,
                timeout=5
            )
        except Exception as e:
            logger.error(f"Error querying HIBP: {str(e)}")
            return Response(
                {'error': 'Error connecting to breach database'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
            
        if response.status_code != 200:
            return Response(
                {'error': 'Error connecting to breach database'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
            
        breach_count = 0
        breach_found = False
        
        for line in response.text.splitlines():
            if ":" in line:
                line_suffix, count = line.split(":", 1)
                if line_suffix == hash_suffix:
                    breach_count = int(count)
                    breach_found = True
                    break
        
        # Compute secure hash of prefix + suffix to detect reuse
        full_hash = hash_prefix + hash_suffix
        sha256_hash = hashlib.sha256(full_hash.encode()).hexdigest()
        
        # Save check history log for authenticated user
        check = PasswordCheck.objects.create(
            user=request.user,
            hash_prefix=hash_prefix,
            sha256_hash=sha256_hash,
            was_breached=breach_found,
            breach_count=breach_count,
            strength_score=0.5, # default audit strength
            entropy=40.0,
            crack_time="minutes",
            recommendation="Change immediately if compromised" if breach_found else "Password is secure"
        )
        
        # Record password check activity in ActivityLog
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')
        from user_agents import parse
        user_agent = parse(request.META.get('HTTP_USER_AGENT', ''))
        browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
        device = f"{user_agent.device.family} ({user_agent.os.family} {user_agent.os.version_string})"
        
        ActivityLog.objects.create(
            user=request.user,
            activity_type='password_check',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            browser=browser[:100],
            device=device[:100]
        )
        
        # Trigger async alert email if compromised
        if breach_found and request.user.receive_breach_notifications:
            send_breach_notification.delay(check.id)
            
        return Response({
            'was_breached': breach_found,
            'breach_count': breach_count,
            'check_id': check.id
        })
        
    @action(detail=False, methods=['post'], url_path='analyze-strength')
    def analyze_strength(self, request):
        """
        Analyze password strength based on characteristics (compatible with frontend password-check.js)
        """
        hash_prefix = request.data.get('hash_prefix', '00000')
        length = int(request.data.get('length', 0))
        has_uppercase = request.data.get('has_uppercase', False)
        has_lowercase = request.data.get('has_lowercase', False)
        has_numbers = request.data.get('has_numbers', False)
        has_symbols = request.data.get('has_symbols', False)
        
        # Estimate strength score based on length and flags (simplified frontend input version)
        score = 0.0
        length_score = min(length / 20, 1.0) * 0.4
        charset_score = 0.0
        if has_lowercase: charset_score += 0.15
        if has_uppercase: charset_score += 0.15
        if has_numbers: charset_score += 0.15
        if has_symbols: charset_score += 0.15
        score = length_score + charset_score
        
        recommendations = []
        if length < 12: recommendations.append("Use at least 12 characters")
        if not has_uppercase: recommendations.append("Add uppercase letters")
        if not has_lowercase: recommendations.append("Add lowercase letters")
        if not has_numbers: recommendations.append("Add numbers")
        if not has_symbols: recommendations.append("Add special characters")
        
        entropy = length * 4.0 # estimate
        
        analysis = PasswordStrengthAnalysis.objects.create(
            user=request.user,
            hash_prefix=hash_prefix,
            strength_score=score,
            entropy=entropy,
            crack_time="minutes",
            recommendations=recommendations
        )
        
        return Response({
            'strength_score': score,
            'recommendations': recommendations,
            'analysis_id': analysis.id
        })


# --- CLEAN REST API ENDPOINTS ---

@api_view(['POST'])
@permission_classes([AllowAny])
def api_check_password(request):
    """
    POST /api/check-password
    
    Accepts:
        password: raw password to check
    """
    password = request.data.get('password')
    if not password:
        return Response({'error': 'password is required'}, status=status.HTTP_400_BAD_REQUEST)
        
    # Perform k-Anonymity breach check
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    breach_count = 0
    was_breached = False
    
    try:
        api_client = HaveIBeenPwnedClient()
        headers = {'User-Agent': 'PasswordBreachDetector/1.0'}
        if api_client.api_key:
            headers['hibp-api-key'] = api_client.api_key
        response = requests.get(f"{api_client.API_BASE_URL}/range/{prefix}", headers=headers, timeout=5)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if ":" in line:
                    line_suffix, count = line.split(":", 1)
                    if line_suffix == suffix:
                        breach_count = int(count)
                        was_breached = True
                        break
    except Exception as e:
        logger.error(f"API checking error: {str(e)}")
        
    # Analyze strength & entropy
    score, entropy, crack_time, recs = analyze_password_strength_raw(password)
    
    # Save check history log if user is logged in
    check_id = None
    if request.user.is_authenticated:
        sha256_hash = hashlib.sha256(sha1_hash.encode()).hexdigest()
        
        check = PasswordCheck.objects.create(
            user=request.user,
            hash_prefix=prefix,
            sha256_hash=sha256_hash,
            was_breached=was_breached,
            breach_count=breach_count,
            strength_score=score,
            entropy=entropy,
            crack_time=crack_time,
            recommendation=", ".join(recs) if recs else "Password looks good!"
        )
        check_id = check.id
        
        # Log password check in user activity history
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')
        from user_agents import parse
        user_agent = parse(request.META.get('HTTP_USER_AGENT', ''))
        browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
        device = f"{user_agent.device.family} ({user_agent.os.family} {user_agent.os.version_string})"
        
        ActivityLog.objects.create(
            user=request.user,
            activity_type='password_check',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            browser=browser[:100],
            device=device[:100]
        )
        
        if was_breached and request.user.receive_breach_notifications:
            send_breach_notification.delay(check.id)
            
    return Response({
        'password_check_id': check_id,
        'was_breached': was_breached,
        'breach_count': breach_count,
        'strength_score': score,
        'entropy': entropy,
        'crack_time': crack_time,
        'recommendations': recs
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_history(request):
    """
    GET /api/history
    """
    checks = PasswordCheck.objects.filter(user=request.user)
    serializer = PasswordCheckSerializer(checks, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_dashboard(request):
    """
    GET /api/dashboard
    """
    user = request.user
    checks = PasswordCheck.objects.filter(user=user)
    
    total_checks = checks.count()
    compromised_count = checks.filter(was_breached=True).count()
    
    strong_count = checks.filter(strength_score__gte=0.8).count()
    medium_count = checks.filter(strength_score__gte=0.4, strength_score__lt=0.8).count()
    weak_count = checks.filter(strength_score__lt=0.4).count()
    
    # Calculate security score
    security_score = 100
    has_2fa = user.use_two_factor or user.has_active_2fa
    if not has_2fa:
        security_score -= 20
        
    # Reused count
    reused_groups = checks.values('sha256_hash').annotate(count=Count('id')).filter(count__gt=1)
    reused_count = sum(group['count'] for group in reused_groups) if reused_groups else 0
    
    if total_checks > 0:
        security_score -= (compromised_count * 15)
        security_score -= (reused_count * 10)
    else:
        security_score -= 20
        
    security_score = max(0, min(100, security_score))
    
    return Response({
        'total_checks': total_checks,
        'compromised_count': compromised_count,
        'strong_count': strong_count,
        'medium_count': medium_count,
        'weak_count': weak_count,
        'reused_count': reused_count,
        'security_score': security_score
    })

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def api_generate_password(request):
    """
    GET /api/generate-password
    """
    params = request.query_params if request.method == 'GET' else request.data
    
    length = int(params.get('length', 12))
    uppercase = params.get('uppercase', 'true').lower() == 'true'
    lowercase = params.get('lowercase', 'true').lower() == 'true'
    numbers = params.get('numbers', 'true').lower() == 'true'
    symbols = params.get('symbols', 'true').lower() == 'true'
    exclude_similar = params.get('exclude_similar', 'false').lower() == 'true'
    
    password = generate_secure_password(
        length=length, 
        uppercase=uppercase, 
        lowercase=lowercase, 
        numbers=numbers, 
        symbols=symbols, 
        exclude_similar=exclude_similar
    )
    
    return Response({'password': password})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_security_score(request):
    """
    GET /api/security-score
    """
    user = request.user
    checks = PasswordCheck.objects.filter(user=user)
    
    total_checks = checks.count()
    compromised_count = checks.filter(was_breached=True).count()
    
    reused_groups = checks.values('sha256_hash').annotate(count=Count('id')).filter(count__gt=1)
    reused_count = sum(group['count'] for group in reused_groups) if reused_groups else 0
    
    security_score = 100
    recs = []
    
    has_2fa = user.use_two_factor or user.has_active_2fa
    if not has_2fa:
        security_score -= 20
        recs.append("Enable two-factor authentication (2FA) for your account.")
        
    if total_checks > 0:
        if compromised_count > 0:
            security_score -= (compromised_count * 15)
            recs.append(f"Replace the {compromised_count} compromised passwords detected in your check history.")
            
        if reused_count > 0:
            security_score -= (reused_count * 10)
            recs.append(f"You have {reused_count} checks containing reused passwords. Ensure all passwords are unique.")
    else:
        security_score -= 20
        recs.append("Run check on at least one password to audit your credentials.")
        
    security_score = max(0, min(100, security_score))
    
    return Response({
        'security_score': security_score,
        'recommendations': recs
    })

@api_view(['POST'])
@permission_classes([AllowAny])
def api_ai_advisor_chat(request):
    """
    POST /api/ai-advisor/chat
    Enables users to chat with Sentinel AI, which uses context-aware profile summaries.
    """
    prompt = request.data.get('message', '').strip()
    if not prompt:
        return Response({'error': 'Message parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        from .ai_service import AIService
        response_text, is_fallback = AIService.chat(request.user, prompt)
        return Response({
            'response': response_text,
            'is_fallback': is_fallback
        })
    except Exception as e:
        logger.error(f"AI Advisor view error: {str(e)}")
        # Ultimate fallback response to ensure zero crashes
        return Response({
            'response': "Running in Offline Security Advisor mode. I can help explain entropy, k-Anonymity, and score improvements.",
            'is_fallback': True
        })
