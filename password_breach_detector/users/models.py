from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

class User(AbstractUser):
    """Extended user model with security and notification preferences"""
    email = models.EmailField(_('email address'), unique=True)
    
    # Security settings
    use_two_factor = models.BooleanField(default=False)
    last_security_check = models.DateTimeField(null=True, blank=True)
    
    # Notification preferences
    receive_breach_notifications = models.BooleanField(default=True)
    receive_weekly_reports = models.BooleanField(default=False)
    
    # Analytics (optional for user)
    allow_anonymous_analytics = models.BooleanField(default=True)
    
    # Profile data
    bio = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    
    # Required for using email as the main identifier
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
    
    @property
    def has_active_2fa(self):
        """Check if user has active 2FA"""
        from django_otp import devices_for_user
        return any(device.is_active for device in devices_for_user(self))
    
    @property
    def breach_count(self):
        """Get count of user's passwords found in breaches"""
        return self.password_checks.filter(was_breached=True).count()
