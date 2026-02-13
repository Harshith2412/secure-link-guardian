# SecureLink Guardian - Lightweight Requirements
# No heavy ML packages - faster installation for Python 3.13

# ============================================
# Web Framework & API (REQUIRED)
# ============================================
Flask==3.0.0
Flask-CORS==4.0.0
flask-limiter==3.5.0
Werkzeug==3.0.1
pydantic==2.5.0
python-dotenv==1.0.0

# ============================================
# Web Scraping (REQUIRED)
# ============================================
beautifulsoup4==4.12.2
lxml==5.1.0
requests==2.31.0

# ============================================
# DNS & Network (REQUIRED)
# ============================================
dnspython==2.4.2
python-whois==0.8.0
tldextract==5.1.0

# ============================================
# SSL/TLS (REQUIRED)
# ============================================
pyOpenSSL==23.3.0
cryptography==41.0.7

# ============================================
# Database (REQUIRED)
# ============================================
redis==5.0.1
pymongo==4.6.0

# ============================================
# String Similarity (REQUIRED)
# ============================================
python-Levenshtein==0.23.0
fuzzywuzzy==0.18.0

# ============================================
# NLP - Lightweight (REQUIRED)
# ============================================
nltk==3.8.1
textblob==0.17.1

# ============================================
# Testing (REQUIRED)
# ============================================
pytest==7.4.3
pytest-asyncio==0.21.1

# ============================================
# Utilities (REQUIRED)
# ============================================
python-dateutil==2.8.2
colorlog==6.8.0
click==8.1.7
rich==13.7.0

# ============================================
# Optional - Install separately if needed
# ============================================
# playwright==1.40.0          # For sandbox rendering
# scikit-learn>=1.4.0         # For ML models
# opencv-python==4.8.1.78     # For visual analysis
# Pillow==10.1.0              # For image processing