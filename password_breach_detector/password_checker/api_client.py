import hashlib
import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class HaveIBeenPwnedClient:
    """API client for HaveIBeenPwned service"""
    
    API_BASE_URL = "https://api.pwnedpasswords.com"
    
    def __init__(self):
        self.api_key = settings.HAVEIBEENPWNED_API_KEY
    
    def check_password(self, password):
        """
        Check if a password has been found in known data breaches
        
        Args:
            password (str): The password to check
            
        Returns:
            tuple: (bool, int) - (was_breached, breach_count)
        """
        # Create SHA-1 hash of the password
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Get the first 5 characters (prefix)
        prefix = password_hash[:5]
        
        # Get the rest of the hash to compare against API results
        suffix = password_hash[5:]
        
        try:
            # Query the API with the prefix
            headers = {
                'User-Agent': 'PasswordBreachDetector/1.0',
                'hibp-api-key': self.api_key
            }
            response = requests.get(
                f"{self.API_BASE_URL}/range/{prefix}",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"API error: {response.status_code}")
                return False, 0
            
            # Parse the response to find any matches
            breach_count = 0
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    breach_count = int(count)
                    break
            
            return breach_count > 0, breach_count
            
        except Exception as e:
            logger.exception(f"Error checking password: {str(e)}")
            return False, 0
    
    def get_breached_sites(self, email=None):
        """
        Get a list of sites where an email has been breached
        
        Args:
            email (str, optional): The email to check
            
        Returns:
            list: List of breached sites
        """
        if not email:
            return []
            
        try:
            headers = {
                'User-Agent': 'PasswordBreachDetector/1.0',
                'hibp-api-key': self.api_key
            }
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []
            else:
                logger.error(f"API error checking email: {response.status_code}")
                return []
                
        except Exception as e:
            logger.exception(f"Error checking email: {str(e)}")
            return []
