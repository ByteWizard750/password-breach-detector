from django.db import models
from django.conf import settings

class PasswordCheck(models.Model):
    """Record of a password check with breach details"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_checks'
    )
    # Only store the first 5 characters of the SHA-1 hash for k-anonymity
    hash_prefix = models.CharField(max_length=5)
    
    # Store a SHA-256 of the full SHA-1 hash to detect reuse without storing the password
    sha256_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    
    check_timestamp = models.DateTimeField(auto_now_add=True)
    was_breached = models.BooleanField(default=False)
    breach_count = models.IntegerField(default=0)
    breach_details = models.JSONField(null=True, blank=True)
    notification_sent = models.BooleanField(default=False)
    
    # Let's keep audit details of the checked strength
    strength_score = models.FloatField(default=0.0)  # 0.0 to 1.0
    entropy = models.FloatField(default=0.0)
    crack_time = models.CharField(max_length=100, blank=True)
    recommendation = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-check_timestamp']
        verbose_name_plural = 'Password Checks'
    
    def __str__(self):
        return f"{self.user.email} - {self.check_timestamp}"

class PasswordStrengthAnalysis(models.Model):
    """Password strength analysis results"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='strength_analyses'
    )
    hash_prefix = models.CharField(max_length=5)
    strength_score = models.FloatField()  # 0.0 to 1.0
    entropy = models.FloatField(default=0.0)
    crack_time = models.CharField(max_length=100, blank=True)
    analysis_timestamp = models.DateTimeField(auto_now_add=True)
    recommendations = models.JSONField()
    
    class Meta:
        ordering = ['-analysis_timestamp']
        verbose_name_plural = 'Password Strength Analyses'
    
    def __str__(self):
        return f"{self.user.email} - Score: {self.strength_score}"
