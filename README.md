# 🧠 Phishing URL Detector 🚨

A machine learning tool that detects phishing URLs using Random Forest classification and threat intelligence APIs (Google Safe Browsing & VirusTotal).

---

## ✨ Features

- 🤖 **Machine Learning**: Random Forest model trained on 10,000 URLs
- 🛡️ **API Integration**: VirusTotal & Google Safe Browsing verification
- 🌐 **Web Interface**: Easy-to-use Flask web app
- 📊 **30+ Features**: Extracts security-related URL characteristics
- ⚡ **Fast Results**: Combines ML predictions with real-time API checks

---

## 🚀 Quick Start

### 1. Setup
```bash
# Clone repository
git clone https://github.com/FirdawsM/Brainwave_Matrix_Intern_T1.git
cd Brainwave_Matrix_Intern_T1

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure API Keys
Create a `.env` file:
```bash
VIRUSTOTAL_API_KEY=your_virustotal_key
GOOGLE_API_KEY=your_google_key
```

Get free API keys:
- [VirusTotal](https://www.virustotal.com/gui/join-us) (4 requests/minute)
- [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) (10k requests/day)

### 3. Run Application
```bash
python phishing_detector.py
```
Open: http://localhost:5000

---

## 💻 Usage

### Web Interface
1. Enter URL in the input box
2. Click "Scan URL"
3. View results: **SAFE**, **SUSPICIOUS**, or **PHISHING**

### API Endpoint
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "prediction": "SAFE",
  "confidence": 0.92,
  "virustotal_result": {"positives": 0},
  "google_safe_browsing": {"threat_detected": false}
}
```

---

## 🛠️ Technical Details

### Dataset
- **Source**: Kaggle phishing dataset
- **Size**: 10,000 URLs (50% phishing, 50% legitimate)
- **Features**: 30+ URL characteristics (HTTPS, domain length, special characters, etc.)

### Model
- **Algorithm**: Random Forest Classifier
- **Accuracy**: 85.2%
- **Files**: `phishing_model.pkl`, `scaler.pkl`

### File Structure
```
├── phishing_detector.py    # Main Flask app
├── phishing_model.pkl      # Trained model
├── scaler.pkl             # Feature scaler
├── templates/             # HTML files
├── static/               # CSS/JS files
└── requirements.txt      # Dependencies
```

---

## 📝 Requirements

**Python Packages:**
```
flask
scikit-learn
pandas
numpy
requests
python-dotenv
```

**API Keys** (free tier available):
- VirusTotal API
- Google Safe Browsing API

---

![First scan ](https://github.com/user-attachments/assets/ad49d234-b69b-4499-915a-d1572b4ae25a)
![first result ](https://github.com/user-attachments/assets/27d5df02-4f43-4c75-aeac-2474aa92b86b)
![Recommendations ](https://github.com/user-attachments/assets/14e3d2f9-cc1e-4857-8e2c-f6f3a1efbe3c)

![suspicious URL scan ](https://github.com/user-attachments/assets/8048001c-bdab-4483-8716-15cb884a0d01)
![malicious URL scan report ](https://github.com/user-attachments/assets/c060655f-9531-4858-b98f-74c6d45d459f)
![malicious URL scan recommendation](https://github.com/user-attachments/assets/1de9cde7-1d34-4a5e-a54b-be8958a7924a)




## 👨‍💻 Author

**Firdaws Mohammed**  
*Brainwave Matrix Internship - Task 1*

🔗 GitHub: [@FirdawsM](https://github.com/FirdawsM)

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

*Part of Brainwave Matrix Solutions Internship Program*
