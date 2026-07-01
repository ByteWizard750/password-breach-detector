from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from django.conf import settings
from django.conf.urls.static import static

from users import views as users_views
from password_checker import views as checker_views

router = DefaultRouter()
router.register(r'api/password', checker_views.PasswordCheckViewSet, basename='password')

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Static pages
    path('', users_views.home, name='home'),
    path('about/', users_views.about, name='about'),
    path('contact/', users_views.contact, name='contact'),
    path('privacy/', users_views.privacy, name='privacy'),
    path('terms/', users_views.terms, name='terms'),
    
    # Authentication & Dashboard
    path('dashboard/', users_views.dashboard, name='dashboard'),
    path('accounts/signup/', users_views.account_signup, name='account_signup'),
    path('accounts/login/', users_views.account_login, name='account_login'),
    path('accounts/logout/', users_views.account_logout, name='account_logout'),
    
    # 2FA
    path('security/2fa/setup/', users_views.two_factor_setup, name='two_factor_setup'),
    path('security/2fa/disable/', users_views.two_factor_disable, name='two_factor_disable'),
    path('security/2fa/verify/', users_views.two_factor_verify, name='two_factor_verify'),
    
    # History & Analytics
    path('password/check/', users_views.password_check, name='password_check'),
    path('password/history/', users_views.breach_history, name='breach_history'),
    path('password/health/', users_views.password_health, name='password_health'),
    path('activity/history/', users_views.activity_history, name='activity_history'),
    
    # Settings & Profile
    path('profile/', users_views.profile, name='profile'),
    path('settings/profile/', users_views.account_settings, name='account_settings'),
    path('settings/security/', users_views.security_settings, name='security_settings'),
    path('settings/privacy/', users_views.data_privacy, name='data_privacy'),
    
    # --- CLEAN REST API ENDPOINTS ---
    path('api/check-password', checker_views.api_check_password, name='api_check_password'),
    path('api/history', checker_views.api_history, name='api_history'),
    path('api/dashboard', checker_views.api_dashboard, name='api_dashboard'),
    path('api/generate-password', checker_views.api_generate_password, name='api_generate_password'),
    path('api/security-score', checker_views.api_security_score, name='api_security_score'),
    path('api/ai-advisor/chat', checker_views.api_ai_advisor_chat, name='api_ai_advisor_chat'),
    
    # Viewset endpoints (for frontend password-check.js)
    path('', include(router.urls)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
