# 🔒 Password Breach Detector

A Django-based web application that allows users to securely check if their password has been exposed in known data breaches. The app uses the Have I Been Pwned API with k-Anonymity for privacy protection and integrates Celery to send asynchronous email alerts for compromised passwords.

---

## ✅ Features

- 🔐 Check if passwords are part of known breaches
- 🛡️ Uses k-Anonymity (only first 5 hash chars sent to API)
- 📧 Sends email alerts for breached passwords
- ⚙️ Asynchronous background processing with Celery
- 📊 Password check history and analysis

---

## 🧰 Tech Stack

- **Backend:** Django, Celery
- **Frontend:** HTML, CSS, JavaScript
- **API:** [Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- **Task Queue:** Redis (for Celery)

---

