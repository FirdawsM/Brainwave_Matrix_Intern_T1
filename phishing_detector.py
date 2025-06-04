import base64
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import tldextract
import ipaddress
from sklearn.ensemble import RandomForestClassifier
import joblib
from flask import Flask, request, jsonify, render_template
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import warnings
import os
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from dotenv import load_dotenv  

# Suppress warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

# ========================
# CONFIGURATION
# ========================
load_dotenv()  # Load environment variables from .env file
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

if not VIRUSTOTAL_API_KEY or not GOOGLE_API_KEY:
    raise ValueError("API keys not found in environment variables. Please create a .env file.")

MAX_API_RETRIES = 3
API_TIMEOUT = 10  # seconds
CACHE_SIZE = 1000

# ========================
# DATA PROCESSING
# ========================

def load_dataset():
    """Load and preprocess the phishing dataset"""
    try:
        if os.path.exists('phishing_dataset_clean.csv'):
            return pd.read_csv('phishing_dataset_clean.csv')
        
        df = pd.read_csv('Phishing_Legitimate_full.csv')
        
        # Clean and prepare dataset
        if 'CLASS_LABEL' not in df.columns:
            df['CLASS_LABEL'] = df.iloc[:, -1]
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df = df[numeric_cols].dropna()
        df.to_csv('phishing_dataset_clean.csv', index=False)
        
        return df
    except Exception as e:
        print(f"Dataset loading error: {str(e)}")
        raise

# =====================
# FEATURE EXTRACTION
# =====================

class URLFeatureExtractor:
    """Advanced URL feature extraction with error handling"""
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'update', 'security',
        'banking', 'paypal', 'ebay', 'amazon', 'apple', 'support'
    ]
    
    def __init__(self, url):
        self.url = url
        try:
            self.parsed = urlparse(url)
            self.ext = tldextract.extract(url)
            self.domain = self.ext.domain
            self.suffix = self.ext.suffix
            self.full_domain = f"{self.domain}.{self.suffix}" if self.domain and self.suffix else ""
        except Exception as e:
            print(f"URL parsing error: {e}")
            self.parsed = None
            self.ext = None
            self.domain = ""
            self.suffix = ""
            self.full_domain = ""
        
        self.features = {}
    
    def extract_all_features(self):
        """Comprehensive feature extraction pipeline"""
        try:
            if not self.parsed:
                raise ValueError("URL parsing failed")
                
            self._extract_basic_features()
            self._extract_domain_features()
            self._extract_security_features()
            
            # Set safe defaults for missing features
            self._set_default_features()
            return self.features
            
        except Exception as e:
            print(f"Feature extraction failed: {e}")
            return self._get_default_features()

    def _extract_basic_features(self):
        """Extract structural URL features"""
        url = self.url.lower()
        self.features.update({
            'NumDots': url.count('.'),
            'SubdomainLevel': len(self.ext.subdomain.split('.')) if self.ext.subdomain else 0,
            'PathLevel': len(self.parsed.path.split('/')) - 1 if self.parsed.path else 0,
            'UrlLength': len(url),
            'NumDash': url.count('-'),
            'NumDashInHostname': self.parsed.netloc.count('-'),
            'AtSymbol': int('@' in url),
            'TildeSymbol': int('~' in url),
            'NumUnderscore': url.count('_'),
            'NumPercent': url.count('%'),
            'NumQueryComponents': len(self.parsed.query.split('&')) if self.parsed.query else 0,
            'NumAmpersand': url.count('&'),
            'NumHash': url.count('#'),
            'NumNumericChars': sum(c.isdigit() for c in url),
            'NoHttps': int(self.parsed.scheme != 'https')
        })

    def _extract_domain_features(self):
        """Extract domain-specific features"""
        self.features.update({
            'HostnameLength': len(self.parsed.netloc),
            'PathLength': len(self.parsed.path),
            'QueryLength': len(self.parsed.query),
            'IpAddress': int(self._is_ip_address())
        })

    def _extract_security_features(self):
        """Extract security-related indicators"""
        path = self.parsed.path.lower()
        self.features.update({
            'DoubleSlashInPath': int('//' in path),
            'RandomString': int(bool(re.search(r'[0-9a-f]{8}', self.url, re.I))),
            'DomainInSubdomains': int(bool(self.domain and self.domain in self.ext.subdomain)),
            'DomainInPaths': int(bool(self.domain and self.domain in path)),
            'HttpsInHostname': int('https' in self.parsed.netloc),
            'NumSensitiveWords': sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in self.url.lower()),
            'EmbeddedBrandName': int(any(brand in self.url.lower() for brand in ['paypal', 'ebay', 'amazon', 'bank']))
        })

    def _is_ip_address(self):
        """Check if hostname is an IP address"""
        try:
            ipaddress.ip_address(self.parsed.netloc)
            return True
        except:
            return False

    def _set_default_features(self):
        """Set default values for optional features"""
        self.features.update({
            'PctExtHyperlinks': 0.5,
            'PctExtResourceUrls': 0.5,
            'ExtFavicon': 0,
            'InsecureForms': 0,
            'RelativeFormAction': 0,
            'ExtFormAction': 0,
            'AbnormalFormAction': 0,
            'PctNullSelfRedirectHyperlinks': 0.5,
            'FrequentDomainNameMismatch': 0,
            'FakeLinkInStatusBar': 0,
            'RightClickDisabled': 0,
            'PopUpWindow': 0,
            'SubmitInfoToEmail': 0,
            'IframeOrFrame': 0,
            'MissingTitle': 0,
            'ImagesOnlyInForm': 0
        })

    def _get_default_features(self):
        """Return safe default feature set"""
        dataset_cols = [col for col in load_dataset().columns if col not in ['id', 'CLASS_LABEL']]
        return {col: 0 for col in dataset_cols}

# =====================
# API INTEGRATION
# =====================

@lru_cache(maxsize=CACHE_SIZE)
def check_virustotal(url):
    """Check URL with VirusTotal API with caching"""
    for attempt in range(MAX_API_RETRIES):
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            
            # First, check if URL already has a report
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            # If we get a good response, return the stats
            if analysis_resp.status_code == 200:
                stats = analysis_resp.json()["data"]["attributes"]["last_analysis_stats"]
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
            
            # If not found (404), submit URL for analysis
            elif analysis_resp.status_code == 404:
                submit_resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=API_TIMEOUT
                )
                submit_resp.raise_for_status()
                
                # Return that we've submitted for analysis but don't have results yet
                return {
                    "status": "submitted",
                    "message": "URL submitted for analysis. Please check back later."
                }
            
            analysis_resp.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            print(f"VirusTotal attempt {attempt + 1} failed: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"VirusTotal processing error: {e}")
    
    return None

def check_google_safebrowsing(url):
    """Check URL with Google Safe Browsing API"""
    for attempt in range(MAX_API_RETRIES):
        try:
            payload = {
                "client": {
                    "clientId": "phishing-detector",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
                json=payload,
                timeout=API_TIMEOUT
            )
            response.raise_for_status()
            return bool(response.json().get("matches"))
            
        except requests.exceptions.RequestException as e:
            print(f"Google Safe Browsing attempt {attempt + 1} failed: {e}")
            time.sleep(2)
        except Exception as e:
            print(f"Google Safe Browsing processing error: {e}")
    
    return None

def hybrid_check(url):
    """Enhanced hybrid check with weighted decision system"""
    with ThreadPoolExecutor() as executor:
        vt_future = executor.submit(check_virustotal, url)
        gsb_future = executor.submit(check_google_safebrowsing, url)
        local_future = executor.submit(detector.predict_url, url)
        
        try:
            vt_result = vt_future.result(timeout=API_TIMEOUT + 5)
            gsb_result = gsb_future.result(timeout=API_TIMEOUT + 5)
            local_result = local_future.result(timeout=API_TIMEOUT + 5)
        except Exception as e:
            print(f"Hybrid check timeout: {e}")
            vt_result, gsb_result = None, None
            local_result = detector.predict_url(url)

    # Initialize result with more detailed structure
    result = {
        "url": url,
        "final_decision": "UNKNOWN",
        "confidence": 0,
        "reasons": [],
        "virustotal": vt_result,
        "google_safe_browsing": gsb_result,
        "local_result": local_result,
        "detailed_analysis": {}
    }

    # Weighted decision system
    decision_points = []
    
    # 1. Google Safe Browsing (Highest weight)
    if gsb_result is True:
        decision_points.append(("Google Safe Browsing detection", 0.9))
        result["reasons"].append("Flagged by Google Safe Browsing")
        result["detailed_analysis"]["google_safe_browsing"] = "Malicious URL detected"
    
    # 2. VirusTotal analysis
    if vt_result and isinstance(vt_result, dict):
        malicious_score = min(1.0, (vt_result["malicious"] * 0.1 + vt_result["suspicious"] * 0.05))
        if malicious_score > 0.2:  # Threshold for considering VT results
            decision_points.append((f"Flagged by {vt_result['malicious']} security engines", malicious_score))
            result["reasons"].append(f"Flagged by {vt_result['malicious']} security engines")
        result["detailed_analysis"]["virustotal"] = vt_result
    
    # 3. Local model analysis
    local_prob = local_result.get("probability", 0)
    if local_prob > 0.5:  # Only consider if probability > 50%
        decision_points.append(("Local model detection", local_prob))
        result["reasons"].append("Local model detected potential phishing")
    
    # 4. Heuristic checks from features
    features = local_result.get("features", {})
    heuristic_score = 0
    
    # Brand impersonation check
    if features.get('EmbeddedBrandName', 0) or features.get('BrandInSubdomain', 0):
        heuristic_score += 0.3
        result["reasons"].append("Brand name detected in URL")
    
    # Suspicious TLD check
    if features.get('SuspiciousTLD', 0):
        heuristic_score += 0.2
        result["reasons"].append("Suspicious top-level domain detected")
    
    # No HTTPS check
    if features.get('NoHttps', 0) and any(kw in url.lower() for kw in ['login', 'account', 'bank']):
        heuristic_score += 0.2
        result["reasons"].append("No HTTPS on sensitive page")
    
    if heuristic_score > 0:
        decision_points.append(("Heuristic analysis", heuristic_score))
    
    # Calculate final confidence
    if decision_points:
        total_weight = sum(weight for (_, weight) in decision_points)
        weighted_sum = sum(weight * score for (_, weight), score in zip(decision_points, [score for (_, score) in decision_points]))
        final_confidence = min(100, int(weighted_sum * 100))
        
        if total_weight >= 0.7:
            result["final_decision"] = "PHISHING"
        elif total_weight >= 0.5:
            result["final_decision"] = "SUSPICIOUS"
        else:
            result["final_decision"] = "SAFE"
        
        result["confidence"] = final_confidence
    else:
        result["final_decision"] = "SAFE"
        result["confidence"] = 85  # Default safe confidence
    
    return result
# =====================
# MACHINE LEARNING MODEL
# =====================

class PhishingDetector:
    """Machine learning model handler with integrated scaler"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
    
    def train_or_load_model(self):
        """Initialize model from disk or train new one"""
        try:
            if all(os.path.exists(f) for f in ['phishing_model.pkl', 'scaler.pkl', 'feature_names.pkl']):
                self.model = joblib.load('phishing_model.pkl')
                self.scaler = joblib.load('scaler.pkl')
                self.feature_names = joblib.load('feature_names.pkl')
                
                if not hasattr(self.model, 'feature_names_in_'):
                    self.model.feature_names_in_ = self.feature_names
                
                print("Loaded pre-trained model")
                return
        except Exception as e:
            print(f"Model loading error: {e}")
        
        self._train_new_model()
    
    def _train_new_model(self):
        """Train and save new classification model"""
        df = load_dataset()
        X = df.drop(['id', 'CLASS_LABEL'], axis=1, errors='ignore')
        y = df['CLASS_LABEL']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_leaf=1,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)
        
        self.feature_names = list(X.columns)
        joblib.dump(self.model, 'phishing_model.pkl')
        joblib.dump(self.scaler, 'scaler.pkl')
        joblib.dump(self.feature_names, 'feature_names.pkl')
        
        print(f"Model trained - Train Accuracy: {self.model.score(X_train_scaled, y_train):.2f}, "
              f"Test Accuracy: {self.model.score(X_test_scaled, y_test):.2f}")
    
    def predict_url(self, url):
        """Predict phishing probability for a URL"""
        try:
            features = URLFeatureExtractor(url).extract_all_features()
            features_df = pd.DataFrame([features])
            
            # Ensure correct feature order and fill missing
            for col in self.feature_names:
                if col not in features_df:
                    features_df[col] = 0
            
            features_df = features_df[self.feature_names]
            features_scaled = self.scaler.transform(features_df)
            
            pred = self.model.predict(features_scaled)[0]
            proba = self.model.predict_proba(features_scaled)[0][1]
            
            return {
                'url': url,
                'is_phishing': bool(pred),
                'probability': float(proba),
                'features': features
            }
        except Exception as e:
            print(f"Prediction failed: {e}")
            return {
                'url': url,
                'is_phishing': False,
                'probability': 0.0,
                'error': str(e)
            }

# Initialize detector
detector = PhishingDetector()
detector.train_or_load_model()

# =====================
# FLASK APPLICATION
# =====================

@app.route('/')
@app.route('/index')  # Handle both routes
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests with proper error handling"""
    url = request.form.get('url', '').strip()
    if not url:
        return render_template('index.html', error="Please enter a URL")
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = hybrid_check(url)
        
        # Prepare template data
        template_data = {
            'url': result['url'],
            'status': result['final_decision'],
            'confidence': result['confidence'],
            'probability': result['confidence'] / 100,
            'is_phishing': result['final_decision'] in ['PHISHING', 'SUSPICIOUS'],
            'reasons': result['reasons'],
            'virustotal': result.get('virustotal'),
            'features': result['local_result'].get('features', {})
        }
        
        return render_template('results.html', result=template_data)
    
    except Exception as e:
        print(f"Scan error: {e}")
        return render_template('index.html', error=f"Scan failed: {str(e)}")

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for JSON responses"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        result = hybrid_check(url)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)