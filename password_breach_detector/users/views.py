from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse

import base64
from user_agents import parse
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import ActivityLog, User
from .forms import UserRegistrationForm, UserLoginForm, UserProfileForm
from password_checker.models import PasswordCheck, PasswordStrengthAnalysis
from password_checker.views import analyze_password_strength_raw

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'home.html')

def account_signup(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, "Registration successful! Welcome to the Password Security Platform.")
            return redirect('dashboard')
        else:
            messages.error(request, "Registration failed. Please correct the errors below.")
    else:
        form = UserRegistrationForm()
    return render(request, 'account/signup.html', {'form': form})

def account_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            remember_me = form.cleaned_data['remember_me']
            
            # Authenticate user using email (since USERNAME_FIELD = 'email')
            user = authenticate(request, username=email, password=password)
                
            if user is not None:
                # Check if 2FA is active
                has_2fa = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
                if has_2fa:
                    # Save user ID in session temporarily and redirect to 2FA verification view
                    request.session['pre_2fa_user_id'] = user.id
                    request.session['remember_me'] = remember_me
                    return redirect('two_factor_verify')
                
                auth_login(request, user)
                if not remember_me:
                    request.session.set_expiry(0) # expires on browser close
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid email or password.")
    else:
        form = UserLoginForm()
    return render(request, 'account/login.html', {'form': form})

def account_logout(request):
    auth_logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('home')

@login_required
def dashboard(request):
    user = request.user
    checks = PasswordCheck.objects.filter(user=user)
    
    total_checks = checks.count()
    compromised_count = checks.filter(was_breached=True).count()
    
    strong_count = checks.filter(strength_score__gte=0.8).count()
    medium_count = checks.filter(strength_score__gte=0.4, strength_score__lt=0.8).count()
    weak_count = checks.filter(strength_score__lt=0.4).count()
    
    # Calculate security score (0-100)
    security_score = 100
    security_recommendations = []
    security_alerts = []
    
    # Check 2FA
    has_2fa = user.use_two_factor or user.has_active_2fa
    if not has_2fa:
        security_score -= 20
        security_recommendations.append("Enable two-factor authentication (2FA) for your account.")
        security_alerts.append({
            'title': '2FA Disabled',
            'description': 'Your account is vulnerable to credential stuffing. Enable 2FA now.',
            'severity': 'high',
            'action_url': reverse('security_settings'),
            'action_text': 'Enable 2FA'
        })
        
    # Reused count
    reused_groups = checks.values('sha256_hash').annotate(count=Count('id')).filter(count__gt=1)
    reused_count = sum(group['count'] for group in reused_groups) if reused_groups else 0
    
    if total_checks > 0:
        if compromised_count > 0:
            security_score -= (compromised_count * 15)
            security_recommendations.append(f"Replace the {compromised_count} compromised passwords detected in your check history.")
            security_alerts.append({
                'title': 'Compromised Passwords Detected',
                'description': f'We found {compromised_count} compromised passwords in your checks. Replace them immediately.',
                'severity': 'high',
                'action_url': reverse('breach_history'),
                'action_text': 'View Breaches'
            })
            
        if reused_count > 0:
            security_score -= (reused_count * 10)
            security_recommendations.append(f"Change reused passwords. Unique passwords should be used for every account.")
            security_alerts.append({
                'title': 'Reused Passwords Detected',
                'description': f'You checked {reused_count} identical passwords. Avoid password reuse.',
                'severity': 'medium',
                'action_url': reverse('breach_history'),
                'action_text': 'Fix Reuse'
            })
    else:
        security_score -= 20
        security_recommendations.append("Audit at least one password to start checking your score.")
        
    security_score = max(0, min(100, security_score))
    
    # Recent checks and activities
    recent_checks = checks[:5]
    recent_activities = ActivityLog.objects.filter(user=user)[:5]
    
    password_stats = {
        'strong': strong_count,
        'medium': medium_count,
        'weak': weak_count,
        'compromised': compromised_count
    }
    
    context = {
        'security_score': security_score,
        'security_recommendations': security_recommendations,
        'security_alerts': security_alerts,
        'recent_activities': recent_activities,
        'recent_checks': recent_checks,
        'password_stats': password_stats,
    }
    return render(request, 'partials/dashboard.html', context)

@login_required
def password_check(request):
    return render(request, 'partials/password_check.html')

@login_required
def breach_history(request):
    user = request.user
    query = request.GET.get('q', '')
    status_filter = request.GET.get('status', 'all')
    
    checks = PasswordCheck.objects.filter(user=user)
    
    if query:
        checks = checks.filter(hash_prefix__icontains=query)
        
    if status_filter == 'compromised':
        checks = checks.filter(was_breached=True)
    elif status_filter == 'clean':
        checks = checks.filter(was_breached=False)
        
    paginator = Paginator(checks, 10) # 10 checks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'partials/breach_history.html', {
        'page_obj': page_obj,
        'query': query,
        'status_filter': status_filter
    })

@login_required
def activity_history(request):
    user = request.user
    logs = ActivityLog.objects.filter(user=user)
    
    paginator = Paginator(logs, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'partials/activity_history.html', {'page_obj': page_obj})

@login_required
def password_health(request):
    user = request.user
    checks = PasswordCheck.objects.filter(user=user)
    
    strong = checks.filter(strength_score__gte=0.8).count()
    medium = checks.filter(strength_score__gte=0.4, strength_score__lt=0.8).count()
    weak = checks.filter(strength_score__lt=0.4).count()
    compromised = checks.filter(was_breached=True).count()
    
    # Timeline data for checks (last 10 checks)
    timeline_checks = list(reversed(checks[:10]))
    timeline_labels = [c.check_timestamp.strftime('%b %d') for c in timeline_checks]
    timeline_scores = [round(c.strength_score * 100) for c in timeline_checks]
    
    # Password reuse details
    reused_groups = checks.values('sha256_hash').annotate(count=Count('id')).filter(count__gt=1)
    reused_list = []
    for g in reused_groups:
        prefix = checks.filter(sha256_hash=g['sha256_hash']).first().hash_prefix
        reused_list.append({
            'hash_prefix': prefix,
            'count': g['count']
        })
        
    context = {
        'stats': {
            'strong': strong,
            'medium': medium,
            'weak': weak,
            'compromised': compromised,
            'total': checks.count()
        },
        'timeline_labels': timeline_labels,
        'timeline_scores': timeline_scores,
        'reused_list': reused_list
    }
    return render(request, 'partials/password_health.html', context)

@login_required
def account_settings(request):
    user = request.user
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            
            # Log setting update in ActivityLog
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')
            ActivityLog.objects.create(
                user=user,
                activity_type='profile_update',
                ip_address=ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                browser='Generic Browser',
                device='Generic Device'
            )
            
            messages.success(request, "Profile settings updated successfully.")
            return redirect('account_settings')
    else:
        form = UserProfileForm(instance=user)
    return render(request, 'partials/account_settings.html', {'form': form})

@login_required
def profile(request):
    return render(request, 'partials/profile.html')

@login_required
def security_settings(request):
    user = request.user
    has_2fa = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
    return render(request, 'partials/security_settings.html', {'has_2fa': has_2fa})

@login_required
def two_factor_setup(request):
    user = request.user
    # Find or create unconfirmed device
    device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
    if not device:
        # Check if they already have a confirmed device
        if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
            messages.warning(request, "Two-factor authentication is already active.")
            return redirect('security_settings')
        device = TOTPDevice.objects.create(user=user, name="default", confirmed=False)
        
    # Get configuration secret & URL
    secret_base32 = base64.b32encode(device.bin_key).decode('utf-8')
    config_url = device.config_url
    
    if request.method == 'POST':
        token = request.POST.get('token')
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            
            # Set user flag
            user.use_two_factor = True
            user.save()
            
            # Log activity
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')
            ActivityLog.objects.create(
                user=user,
                activity_type='setting_change',
                ip_address=ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                browser='Generic Browser',
                device='Generic Device'
            )
            
            messages.success(request, "Two-factor authentication has been enabled successfully!")
            return redirect('security_settings')
        else:
            messages.error(request, "Invalid verification code. Please try again.")
            
    return render(request, 'account/two_factor_setup.html', {
        'secret': secret_base32,
        'config_url': config_url
    })

@login_required
def two_factor_disable(request):
    user = request.user
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=user).delete()
        user.use_two_factor = False
        user.save()
        
        # Log activity
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR', '0.0.0.0')
        ActivityLog.objects.create(
            user=user,
            activity_type='setting_change',
            ip_address=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            browser='Generic Browser',
            device='Generic Device'
        )
        
        messages.success(request, "Two-factor authentication has been disabled.")
    return redirect('security_settings')

def two_factor_verify(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('account_login')
        
    user = get_object_or_404(User, id=user_id)
    device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
    
    if request.method == 'POST':
        token = request.POST.get('token')
        if device and device.verify_token(token):
            auth_login(request, user)
            remember_me = request.session.get('remember_me', False)
            if not remember_me:
                request.session.set_expiry(0)
            # clean session
            del request.session['pre_2fa_user_id']
            if 'remember_me' in request.session:
                del request.session['remember_me']
                
            messages.success(request, f"Welcome back, {user.username}! 2FA verified.")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid verification code. Please try again.")
            
    return render(request, 'account/two_factor_verify.html')

@login_required
def data_privacy(request):
    user = request.user
    user.allow_anonymous_analytics = not user.allow_anonymous_analytics
    user.save()
    messages.success(request, "Privacy preferences updated.")
    return redirect('account_settings')

# Basic Informational pages
def privacy(request):
    return render(request, 'info/privacy.html')

def terms(request):
    return render(request, 'info/terms.html')

def about(request):
    return render(request, 'info/about.html')

def contact(request):
    return render(request, 'info/contact.html')
