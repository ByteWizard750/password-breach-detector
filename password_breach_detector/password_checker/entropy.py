import math

COMMON_WORDS = {
    "password", "123456", "123456789", "12345", "qwerty", "admin", "welcome", "letmein", 
    "password123", "shadow", "monkey", "dragon", "football", "baseball", "trustno1",
    "mustang", "cookie", "charlie", "hunter", "princess", "superman", "batman", "killer"
}

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890",
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik,", "ol."
]

def calculate_entropy(password):
    """Calculate Shannon entropy and return (entropy_bits, character_pool_size)"""
    if not password:
        return 0.0, 0
    
    pool = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_special:
        pool += 33
        
    if pool == 0:
        return 0.0, 0
        
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2), pool

def format_time(seconds):
    """Format seconds into a human-readable duration"""
    if seconds < 1:
        return "instantly"
    
    minute = 60
    hour = 3600
    day = 24 * 3600
    month = 30 * 24 * 3600
    year = 365 * 24 * 3600
    
    if seconds >= year:
        years = seconds / year
        if years > 1_000_000:
            return f"{round(years / 1_000_000, 1)} million years"
        return f"{int(years)} year{'s' if int(years) > 1 else ''}"
    elif seconds >= month:
        months = int(seconds / month)
        return f"{months} month{'s' if months > 1 else ''}"
    elif seconds >= day:
        days = int(seconds / day)
        return f"{days} day{'s' if days > 1 else ''}"
    elif seconds >= hour:
        hours = int(seconds / hour)
        return f"{hours} hour{'s' if hours > 1 else ''}"
    elif seconds >= minute:
        minutes = int(seconds / minute)
        return f"{minutes} minute{'s' if minutes > 1 else ''}"
    else:
        return f"{int(seconds)} second{'s' if int(seconds) > 1 else ''}"

def estimate_crack_times(entropy):
    """Estimate crack time for online, offline, and GPU cracking scenarios"""
    guesses = 2 ** entropy
    
    # Online attack (100 guesses/sec)
    online_sec = guesses / 100
    
    # Offline fast attack (10 billion guesses/sec - simple CPU/single GPU MD5/SHA-1)
    offline_sec = guesses / 10_000_000_000
    
    # GPU rig attack (100 billion guesses/sec - multi-GPU rig)
    gpu_sec = guesses / 100_000_000_000
    
    return {
        "online": format_time(online_sec),
        "offline": format_time(offline_sec),
        "gpu": format_time(gpu_sec)
    }

def check_dictionary_words(password):
    """Check if password contains or is a common dictionary word"""
    p_lower = password.lower()
    for word in COMMON_WORDS:
        if word in p_lower:
            return True, word
    return False, None

def check_sequential_patterns(password):
    """Check for sequential patterns like 'abc', '123'"""
    p_lower = password.lower()
    
    # Check alphabet sequences
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(alphabet) - 2):
        seq = alphabet[i:i+3]
        if seq in p_lower:
            return True, seq
            
    # Check digit sequences
    digits = "01234567890"
    for i in range(len(digits) - 2):
        seq = digits[i:i+3]
        if seq in p_lower:
            return True, seq
            
    return False, None

def check_keyboard_patterns(password):
    """Check for keyboard patterns like 'qwerty', 'asdf'"""
    p_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(pattern) - 3):
            seq = pattern[i:i+4]
            if seq in p_lower:
                return True, seq
    return False, None

def check_repeated_characters(password):
    """Check if character is repeated 3 or more times consecutively"""
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            count += 1
            if count >= 3:
                return True, password[i] * 3
        else:
            count = 1
    return False, None
