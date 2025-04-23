# Objection Management System

A Node.js + MySQL web application that allows **farmers to submit objections** to a central authority and **administrators to manage and resolve them**. Built with Express, Handlebars, and secure user authentication, the app supports password recovery, status tracking, and multi-role dashboards.

---

## 🚀 Features

- 🔐 Secure Farmer & Admin Login (bcrypt-hashed passwords, session-based)
- ✍️ Farmers can:
  - Register and log in
  - Submit new objections (1 active at a time)
  - Track objection status
  - Reset forgotten passwords via verification code
- 🧑‍💼 Admins can:
  - View, review, and resolve pending objections
  - Search objections by transaction number
  - Access a resolved archive
- 🌐 Arabic-language support with localized date formatting
- 🛡️ Uses `helmet` for secure HTTP headers and CSP
- 📦 Bootstrap-based frontend via Handlebars templates

---

## ⚙️ Setup

### 1. Clone & Install

```bash
git clone https://github.com/najwa2222/objc-version1.git
cd objc-version1
npm install
```

Run the App
```bash
npm start
```

Open in browser: http://localhost:3000


Development Notes
The app auto-creates the required tables (farmer, objection, password_reset) on first run.

Use the /debug/env route to verify environment config in development.

🛠 Tech Stack
Backend: Node.js, Express, MySQL

Templating: Handlebars (.hbs)

Security: bcrypt, express-session, helmet, connect-flash

Validation: express-validator

Date Formatting: moment (Arabic + English formats)

Frontend: Bootstrap 5 (via CDN)

