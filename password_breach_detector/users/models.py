from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.conf import settings

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

class ActivityLog(models.Model):
    """Log of user and system security activities"""
    ACTIVITY_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('password_check', 'Password Check'),
        ('password_change', 'Password Change'),
        ('email_change', 'Email Change'),
        ('profile_update', 'Profile Update'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='activity_logs'
    )
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    browser = models.CharField(max_length=100, blank=True)
    device = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100, blank=True, default='Unknown')
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = 'Activity Logs'
        
    def __str__(self):
        return f"{self.user.email} - {self.activity_type} - {self.timestamp}"
