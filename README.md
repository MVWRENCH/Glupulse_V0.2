# GluPulse: Holistic Diabetes Management & Marketplace Ecosystem

![GluPulse Banner](https://via.placeholder.com/1200x300?text=GluPulse+Health+Ecosystem) 
GluPulse is a comprehensive mobile ecosystem designed to bridge the gap between **medical health tracking** and **dietary action** for Type 2 Diabetes management. Unlike passive logbooks, GluPulse integrates clinical data monitoring with a specialized **healthy food marketplace**, orchestrated by **Google Gemini AI** to provide real-time, personalized lifestyle recommendations.

---

## 🚀 Key Features

The system operates on a multi-role architecture (User, Seller, Admin) serving distinct purposes:

### 📱 User (Mobile Application)
* **Clinical Health Logging**: Detailed tracking for **Glucose** (with trend arrows), **HbA1c**, **Medications** (doses & schedules), **Sleep Patterns**, and **Physical Activity**.
* **AI Health Coach (Gemini)**:
    * Generates personalized food and activity recommendations based on current glucose levels and medical profile.
    * Provides "Health Insights" explaining *why* a specific recommendation is made.
* **Smart Marketplace**:
    * Purchase AI-recommended foods directly within the app.
    * Filter foods by **Glycemic Index (GI)**, **Glycemic Load (GL)**, and macro-nutrient composition.
* **Order Tracking**: Real-time status updates from preparation to delivery.

### 🏪 Seller (Web Dashboard)
* **Menu Management**: Upload food items with mandatory nutritional transparency (Calories, Carbs, Sugar, GI, GL).
* **Order Fulfillment**: Real-time incoming order dashboard via WebSockets.
* **Business Analytics**: Track sales performance and product popularity.

### 🛡️ Admin (System Control)
* **Strict Verification**: Approval workflows for new Seller accounts and new Menu items to ensure safety for diabetic users.
* **System Monitoring**: Real-time server health checks, AI token usage logs, and security audit trails.
* **User Management**: Oversight of user accounts and compliance.

---

## 🔒 Security Architecture

GluPulse implements industry-standard security measures to protect sensitive medical data (PHI) and transactional integrity:

* **Multi-Factor Authentication (MFA)**:
    * **OTP (One-Time Password)** verification via Email (SMTP) for Registration, Login, and Password Resets.
    * Time-based expiry (60s) and attempt limiting to prevent brute-force attacks.
* **JWT Authorization**:
    * **Access Tokens** (Short-lived, 15 min) for API access.
    * **Refresh Tokens** (Long-lived, 30 days, Hashed in DB) for secure session rotation.
    * **Token Revocation**: Immediate blacklist capability for compromised sessions.
* **Data Encryption**:
    * Passwords hashed using **Bcrypt**.
    * Sensitive tokens stored as SHA-256 hashes.
* **Role-Based Access Control (RBAC)**: Middleware guards ensure strict separation between User, Seller, and Admin endpoints.

---

## 🧠 AI Engine: How It Works

GluPulse uses a **RAG-like (Retrieval-Augmented Generation)** approach to power its recommendations:

1.  **Context Assembly**: The backend aggregates the user's latest clinical data (e.g., "Fasting Glucose: 140 mg/dL", "Condition: Hypertension") and their dietary preferences.
2.  **Inventory Matching**: The system retrieves available food items from the Marketplace database that match diabetic safety criteria (Low GL/GI).
3.  **Gemini Analysis**: The context and inventory are sent to **Google Gemini**. The LLM analyzes the correlation between the medical state and the food options.
4.  **Actionable Output**: The AI returns a structured recommendation (e.g., "Recommend: Quinoa Salad. Reason: Low GI helps stabilize your current high glucose spike").

---

## 🛠️ Tech Stack

### Backend
* **Language**: Go (Golang) 1.22+
* **Framework**: Echo V4 (High-performance web framework)
* **Database**: PostgreSQL 16 (Relational Data)
* **ORM/Query**: SQLC (Type-safe SQL generation) + PGX Driver
* **AI Integration**: Google Generative AI SDK (Gemini)

### Frontend
* **Mobile**: Flutter (Dart) - Cross-platform (Android/iOS)
* **Web (Seller/Admin)**: HTML5 / Go Templates / Vanilla JS

### Infrastructure
* **Containerization**: Docker
* **Tunnels**: Ngrok (Dev/Testing)
* **Mail Server**: SMTP Integration (Gomail)

---

## 📊 System Validation

The system has undergone rigorous testing to ensure reliability:
* **144 API Endpoints** tested.
* **100% Pass Rate** across Positive and Negative scenarios.
* **UAT Score**: 4.54/5.00 (High User Satisfaction).
* **Performance**: Validated for handling concurrent transaction flows and real-time socket updates.

---

## 📂 Project Structure

GluPulse/
├── cmd/api/            # Application entry point
├── internal/
│   ├── auth/           # JWT, OTP, and OAuth logic
│   ├── database/       # SQLC generated models & queries
│   ├── server/         # Echo server configuration & routes
│   ├── user/           # User & Health handlers
│   ├── seller/         # Seller & Order handlers
│   ├── admin/          # Admin & Verification handlers
│   └── utility/        # Helper functions
├── web/
│   ├── public/         # Static assets (CSS/JS)
│   └── templates/      # HTML views for Web Portals
├── schema.sql          # Database migration files
└── go.mod              # Dependencies

## 🚀 Getting Started

Follow these steps to set up the GluPulse backend locally.

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/your-repo/glupulse.git](https://github.com/your-repo/glupulse.git)
    cd glupulse
    ```

2.  **Configure Environment**
    Create a `.env` file in the root directory and populate it with your credentials:
    ```env
    DATABASE_URL=postgres://user:pass@localhost:5432/glupulse
    port=8080
    SESSION_SECRET=your_jwt_secret
    ADMIN_SECRET_KEY=your_admin_registration_key
    GEMINI_API_KEY=your_google_ai_key
    SMTP_HOST=smtp.gmail.com
    SMTP_USER=your_email
    SMTP_PASS=your_app_password
    ```

3.  **Run Database Migrations**
    Initialize the PostgreSQL database schema:
    ```bash
    make migrate-up
    ```

4.  **Start the Server**
    Launch the API server:
    ```bash
    go run cmd/api/main.go
    ```

---

**© 2026 GluPulse Project. Bina Nusantara University.**
