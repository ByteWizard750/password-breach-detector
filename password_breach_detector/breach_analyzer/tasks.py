from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from .models import PasswordCheck
from users.models import User
from .api_client import HaveIBeenPwnedClient
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_breach_notification(check_id):
    """
    Send email notification about a breached password
    
    Args:
        check_id (int): ID of the PasswordCheck object
    """
    try:
        check = PasswordCheck.objects.get(id=check_id)
        
        # Don't send if notification already sent
        if check.notification_sent:
            return
        
        # Prepare email content
        context = {
            'user': check.user,
            'breach_count': check.breach_count,
            'check_date': check.check_timestamp,
        }
        
        subject = "ALERT: Your Password Was Found in a Data Breach"
        html_message = render_to_string('emails/breach_notification.html', context)
        plain_message = render_to_string('emails/breach_notification.txt', context)
        
        # Send the email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[check.user.email],
            html_message=html_message,
        )
        
        # Update notification status
        check.notification_sent = True
        check.save()
        
        logger.info(f"Breach notification sent to {check.user.email}")
        
    except PasswordCheck.DoesNotExist:
        logger.error(f"Password check with ID {check_id} not found")
    except Exception as e:
        logger.exception(f"Error sending breach notification: {str(e)}")

@shared_task
def check_for_new_breaches():
    """
    Scheduled task to check for new breaches for all users
    """
    logger.info("Starting scheduled breach check for all users")
    
    api_client = HaveIBeenPwnedClient()
    
    # Get users who want notifications
    users = User.objects.filter(receive_breach_notifications=True)
    
    for user in users:
        try:
            # Check user's email for breaches
            breached_sites = api_client.get_breached_sites(user.email)
            
            if not breached_sites:
                continue
                
            # Get the user's last check time
            last_check = user.last_security_check or timezone.now() - timezone.timedelta(days=365)
            
            # Filter breaches that occurred after the last check
            new_breaches = [
                site for site in breached_sites
                if timezone.datetime.strptime(site['AddedDate'], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) > last_check
            ]
            
            if new_breaches:
                # Prepare email content
                context = {
                    'user': user,
                    'new_breaches': new_breaches,
                }
                
                subject = f"ALERT: Your Email Was Found in {len(new_breaches)} New Data Breaches"
                html_message = render_to_string('emails/new_breaches_notification.html', context)
                plain_message = render_to_string('emails/new_breaches_notification.txt', context)
                
                # Send the email
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    html_message=html_message,
                )
                
                logger.info(f"New breaches notification sent to {user.email}")
            
            # Update last check time
            user.last_security_check = timezone.now()
            user.save()
            
        except Exception as e:
            logger.exception(f"Error checking breaches for {user.email}: {str(e)}")
