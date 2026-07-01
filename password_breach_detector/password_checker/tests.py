from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

from .models import PasswordCheck
from .entropy import calculate_entropy, estimate_crack_times, check_sequential_patterns, check_keyboard_patterns
from .views import generate_secure_password, analyze_password_strength_raw

User = get_user_model()

class PasswordEntropyAndStrengthTestCase(TestCase):
    """Test suite for password entropy and strength helpers"""
    
    def test_entropy_calculation(self):
        # Empty string
        ent, pool = calculate_entropy("")
        self.assertEqual(ent, 0.0)
        self.assertEqual(pool, 0)
        
        # Simple digits only
        ent, pool = calculate_entropy("123456")
        self.assertEqual(pool, 10)
        self.assertGreater(ent, 19.0)
        
        # Complex password
        ent, pool = calculate_entropy("ComplexP@ss1")
        # should have lower(26) + upper(26) + digit(10) + special(33) = 95
        self.assertEqual(pool, 95)
        self.assertGreater(ent, 78.0)
        
    def test_crack_times_estimation(self):
        estimates = estimate_crack_times(60.0)
        self.assertIn("online", estimates)
        self.assertIn("offline", estimates)
        self.assertIn("gpu", estimates)
        
    def test_sequential_character_detection(self):
        has_seq, seq = check_sequential_patterns("abc123XYZ")
        self.assertTrue(has_seq)
        
        has_seq, seq = check_sequential_patterns("p@ssword!#")
        self.assertFalse(has_seq)
        
    def test_keyboard_patterns_detection(self):
        has_kb, kb = check_keyboard_patterns("password123qwerty")
        self.assertTrue(has_kb)
        self.assertEqual(kb, "qwer")
        
    def test_raw_strength_analyzer(self):
        score, entropy, gpu_time, recs = analyze_password_strength_raw("short")
        self.assertLess(score, 0.5)
        self.assertTrue(any("longer" in r for r in recs))
        
        score, entropy, gpu_time, recs = analyze_password_strength_raw("Xv9#mQ2!yK5$pL8@")
        self.assertGreaterEqual(score, 0.8)
        self.assertEqual(len(recs), 0)

class PasswordGeneratorTestCase(TestCase):
    """Test suite for password generator features"""
    
    def test_password_generation_parameters(self):
        pw = generate_secure_password(length=16, uppercase=True, lowercase=True, numbers=True, symbols=True)
        self.assertEqual(len(pw), 16)
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(not c.isalnum() for c in pw))
        
        # Test exclude similar
        pw_ex = generate_secure_password(length=30, exclude_similar=True)
        similar_chars = "ilI1o0O9gq8BDS5S2Z"
        self.assertFalse(any(c in similar_chars for c in pw_ex))

class RestApiTestCase(TestCase):
    """Test suite for clean REST API endpoints"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='security_user',
            email='test@securityplatform.com',
            password='StrongUserPassword123!'
        )
        
    def test_api_check_password_anonymous(self):
        url = reverse('api_check_password')
        response = self.client.post(url, {'password': 'PasswordToCheck123!'}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('was_breached', response.json())
        self.assertIn('strength_score', response.json())
        self.assertIn('entropy', response.json())
        
        # Anonymous checks should not be saved in database
        self.assertEqual(PasswordCheck.objects.count(), 0)
        
    def test_api_check_password_authenticated(self):
        self.client.force_login(self.user)
        url = reverse('api_check_password')
        response = self.client.post(url, {'password': 'AuthenticatedCheck99!'}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(PasswordCheck.objects.count(), 1)
        self.assertEqual(PasswordCheck.objects.first().user, self.user)
        
    def test_api_generate_password(self):
        url = reverse('api_generate_password')
        response = self.client.get(url, {'length': 20})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.json()['password']), 20)
        
    def test_api_security_score(self):
        self.client.force_login(self.user)
        url = reverse('api_security_score')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('security_score', response.json())

    def test_api_ai_advisor_chat(self):
        url = reverse('api_ai_advisor_chat')
        # Test anonymous chat
        response = self.client.post(url, {'message': 'What is k-Anonymity?'}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('response', response.json())
        self.assertTrue(response.json()['is_fallback'])
        
        # Test authenticated chat
        self.client.force_login(self.user)
        response = self.client.post(url, {'message': 'Explain my security score'}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('response', response.json())
        self.assertTrue(response.json()['is_fallback'])
