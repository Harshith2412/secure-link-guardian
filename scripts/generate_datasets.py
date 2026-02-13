#!/usr/bin/env python3
"""
SecureLink Guardian - Dataset Generator
Generates sample datasets for training and testing
"""

import csv
import random
import json
from pathlib import Path
from datetime import datetime, timedelta

# Known legitimate domains
LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "github.com",
    "stackoverflow.com", "reddit.com", "youtube.com", "wikipedia.org",
    "paypal.com", "stripe.com", "netflix.com", "spotify.com",
    "dropbox.com", "salesforce.com", "adobe.com", "oracle.com"
]

# Phishing URL patterns
PHISHING_PATTERNS = [
    # Typosquatting
    ("amazon", "amaz0n"), ("paypal", "paypa1"), ("microsoft", "micros0ft"),
    ("apple", "app1e"), ("google", "g00gle"), ("facebook", "facebo0k"),
    
    # Homograph attacks (using similar characters)
    ("amazon", "аmazon"),  # Cyrillic 'а'
    ("paypal", "pаypal"),
    
    # Subdomain abuse
    ("", "amazon-secure"), ("", "paypal-verify"), ("", "microsoft-login"),
    ("", "apple-id-support"), ("", "google-security"),
    
    # Hyphenated variants
    ("", "secure-amazon"), ("", "verify-paypal"), ("", "login-microsoft")
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]

def generate_phishing_urls(count=500):
    """Generate phishing URLs"""
    phishing_urls = []
    
    for i in range(count):
        # Choose a pattern
        if random.random() < 0.4:
            # Typosquatting
            original, typo = random.choice(PHISHING_PATTERNS)
            if original:
                domain = f"{typo}.com"
            else:
                base = random.choice(["amazon", "paypal", "microsoft", "apple"])
                domain = f"{typo}-{base}.com"
        
        elif random.random() < 0.6:
            # Suspicious TLD
            base = random.choice(["secure", "verify", "login", "account"])
            brand = random.choice(["amazon", "paypal", "microsoft", "google"])
            tld = random.choice(SUSPICIOUS_TLDS)
            domain = f"{base}-{brand}{tld}"
        
        else:
            # Subdomain abuse
            subdomain = random.choice(["secure", "verify", "login", "account", "support"])
            base = random.choice(LEGITIMATE_DOMAINS)
            domain = f"{subdomain}.{base}.phishing.com"
        
        # Add protocol
        url = f"https://{domain}"
        
        # Randomly add path
        if random.random() < 0.5:
            paths = ["/login", "/verify", "/account", "/secure", "/update"]
            url += random.choice(paths)
        
        # Randomly add parameters
        if random.random() < 0.3:
            params = ["?redirect=", "?next=", "?return="]
            url += random.choice(params) + "https://malicious.com"
        
        phishing_urls.append({
            'url': url,
            'label': 1,  # Phishing
            'type': 'phishing',
            'created': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat()
        })
    
    return phishing_urls

def generate_legitimate_urls(count=500):
    """Generate legitimate URLs"""
    legitimate_urls = []
    
    for i in range(count):
        domain = random.choice(LEGITIMATE_DOMAINS)
        url = f"https://{domain}"
        
        # Add common paths
        if random.random() < 0.6:
            paths = ["/", "/about", "/contact", "/products", "/services", "/help"]
            url += random.choice(paths)
        
        legitimate_urls.append({
            'url': url,
            'label': 0,  # Legitimate
            'type': 'legitimate',
            'created': (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat()
        })
    
    return legitimate_urls

def save_to_csv(data, filename):
    """Save data to CSV file"""
    filepath = Path(f"datasets/{filename}")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        if data:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    
    print(f"✅ Generated: {filepath} ({len(data)} entries)")

def generate_test_urls():
    """Generate URLs for testing"""
    test_urls = [
        # Known phishing
        {"url": "https://amaz0n-secure-login.com", "expected_risk": "high", "label": 1},
        {"url": "https://paypa1-verify.com", "expected_risk": "high", "label": 1},
        {"url": "https://micros0ft-account.com", "expected_risk": "high", "label": 1},
        {"url": "https://app1e-id-support.com", "expected_risk": "high", "label": 1},
        
        # URL shorteners
        {"url": "https://bit.ly/phishing-test", "expected_risk": "medium", "label": 1},
        {"url": "https://tinyurl.com/malicious", "expected_risk": "medium", "label": 1},
        
        # Suspicious TLDs
        {"url": "https://secure-banking.tk", "expected_risk": "high", "label": 1},
        {"url": "https://verify-account.ml", "expected_risk": "high", "label": 1},
        
        # Legitimate
        {"url": "https://google.com", "expected_risk": "low", "label": 0},
        {"url": "https://microsoft.com", "expected_risk": "low", "label": 0},
        {"url": "https://amazon.com", "expected_risk": "low", "label": 0},
        {"url": "https://github.com", "expected_risk": "low", "label": 0},
    ]
    
    filepath = Path("tests/fixtures/test_urls.json")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(test_urls, f, indent=2)
    
    print(f"✅ Generated: {filepath} ({len(test_urls)} test URLs)")

def generate_phishing_text_samples():
    """Generate phishing text samples for NLP testing"""
    phishing_texts = [
        {
            "text": "URGENT: Your account has been suspended! Click here immediately to verify your identity.",
            "label": 1,
            "urgency_score": 90
        },
        {
            "text": "Security Alert: Unusual activity detected on your account. Verify now to prevent permanent lock.",
            "label": 1,
            "urgency_score": 85
        },
        {
            "text": "Your payment failed. Update your billing information within 24 hours to avoid service interruption.",
            "label": 1,
            "urgency_score": 75
        },
        {
            "text": "Congratulations! You've won $1000. Claim your prize now - limited time offer!",
            "label": 1,
            "urgency_score": 70
        },
        {
            "text": "Thank you for your order. Your package will arrive in 3-5 business days.",
            "label": 0,
            "urgency_score": 10
        },
        {
            "text": "Your monthly statement is now available. Log in to view your account details.",
            "label": 0,
            "urgency_score": 5
        }
    ]
    
    filepath = Path("datasets/phishing_text_samples.json")
    with open(filepath, 'w') as f:
        json.dump(phishing_texts, f, indent=2)
    
    print(f"✅ Generated: {filepath} ({len(phishing_texts)} text samples)")

def main():
    """Main function"""
    print("🔧 Generating datasets...")
    print("")
    
    # Generate phishing URLs
    phishing_urls = generate_phishing_urls(500)
    save_to_csv(phishing_urls, "phishing_urls.csv")
    
    # Generate legitimate URLs
    legitimate_urls = generate_legitimate_urls(500)
    save_to_csv(legitimate_urls, "legitimate_urls.csv")
    
    # Combine for training
    all_urls = phishing_urls + legitimate_urls
    random.shuffle(all_urls)
    save_to_csv(all_urls, "combined_urls.csv")
    
    # Generate test URLs
    generate_test_urls()
    
    # Generate text samples
    generate_phishing_text_samples()
    
    print("")
    print("✅ All datasets generated successfully!")
    print("")
    print("Generated files:")
    print("  - datasets/phishing_urls.csv (500 phishing URLs)")
    print("  - datasets/legitimate_urls.csv (500 legitimate URLs)")
    print("  - datasets/combined_urls.csv (1000 total URLs)")
    print("  - datasets/phishing_text_samples.json (6 text samples)")
    print("  - tests/fixtures/test_urls.json (12 test URLs)")

if __name__ == "__main__":
    main()