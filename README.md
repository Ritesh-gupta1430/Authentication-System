# 🔐 MERN Authentication System (JWT + OTP Email Verification)

This is a **complete Authentication System** built using the **MERN Stack (MongoDB, Express, React, Node.js)**.  
It includes **User Registration, Login, Email Verification with OTP, Password Reset**, and **JWT-based Secure Authentication** — all integrated between frontend and backend.

---

## 🚀 Features

✅ User Registration with Email and Password  
✅ Email Verification using **6-digit OTP**  
✅ Secure Login using **JWT (JSON Web Token)**  
✅ Forgot Password and Reset with OTP verification  
✅ Passwords encrypted with **bcryptjs**  
✅ Responsive Frontend using **React + Tailwind CSS**  
✅ RESTful APIs built with **Express.js**  
✅ Emails sent securely with **Nodemailer + Brevo SMTP**  
✅ Full MERN Integration (Backend ↔ Frontend)

---

## 🧩 Tech Stack

| Layer | Technology |
|-------|-------------|
| Frontend | React.js, Tailwind CSS, Axios |
| Backend | Node.js, Express.js |
| Database | MongoDB (Mongoose) |
| Authentication | JWT (JSON Web Token) |
| Email Service | Nodemailer with Brevo SMTP |
| Security | bcryptjs for password hashing |

---


---

## ⚙️ Installation and Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Ritesh-gupta1430/Authentication-System.git
```

## 2️⃣ Install Dependencies

### Backend
```bash
cd server
npm install
```

### Frontend
```bash
cd ../client
npm install
```

## 3️⃣ Create .env File 
### inside server folder
```bash
MONGODB_URI = 
JWT_SECRET = 
NODE_ENV = 
SMTP_USER = 
SMTP_PASS = 
SENDER_EMAIL = 
CLIENT_URL = 
```

### inside client folder
```bash 
VITE_BACKEND_URL=
```

## 4️⃣ Run the Application

### Start Backend
```bash
cd server
npm start
```

### Start Frontend
```bash
cd ../client
npm start
```

Frontend runs at 👉 http://localhost:5173

Backend runs at 👉 http://localhost:4000


## 📡 API Endpoints
| Method | Endpoint                    | Description                       |
| ------ | --------------------------- | --------------------------------- |
| POST   | `/api/auth/register`        | Register user & send OTP to email |
| POST   | `/api/auth/verify-otp`      | Verify email using OTP            |
| POST   | `/api/auth/login`           | Login user & return JWT token     |
| POST   | `/api/auth/forgot-password` | Send OTP for password reset       |
| POST   | `/api/auth/reset-password`  | Reset password using OTP          |


## 🔒 Security Features

Passwords hashed using bcryptjs before saving.  
JWT tokens ensure secure authentication.  
OTP-based email verification adds extra safety.  
Environment variables protect sensitive credentials.  

## 👨‍💻 Author

**Ritesh Gupta**  
💻 Passionate about Web Development  
📧 Email: riteshrg651@gmail.com  
🌐 GitHub: [Ritesh-gupta1430](https://github.com/Ritesh-gupta1430)

