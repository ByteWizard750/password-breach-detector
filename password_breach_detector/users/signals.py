from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from .models import ActivityLog
from user_agents import parse

def get_client_ip(request):
    if not request:
        return '0.0.0.0'
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip

@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    if request and user:
        ip = get_client_ip(request)
        ua_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(ua_string)
        
        browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
        device = f"{user_agent.device.family} ({user_agent.os.family} {user_agent.os.version_string})"
        
        ActivityLog.objects.create(
            user=user,
            activity_type='login',
            ip_address=ip,
            user_agent=ua_string,
            browser=browser[:100],
            device=device[:100],
            location='Unknown'
        )

@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    if request and user:
        ip = get_client_ip(request)
        ua_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(ua_string)
        
        browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
        device = f"{user_agent.device.family} ({user_agent.os.family} {user_agent.os.version_string})"
        
        ActivityLog.objects.create(
            user=user,
            activity_type='logout',
            ip_address=ip,
            user_agent=ua_string,
            browser=browser[:100],
            device=device[:100],
            location='Unknown'
        )
