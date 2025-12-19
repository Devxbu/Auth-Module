# NodeJS Authentication Service

This is a robust authentication microservice built with Node.js, Express, MongoDB, and Redis. It handles user registration, login, secure token management (using JWT and Refresh Tokens), and password recovery updates.

## 🚀 Features

- **User Registration & Login**
- **JWT Authentication** (Access & Refresh tokens)
- **Token Management** (Refresh, Logout, Logout All Devices)
- **Password Recovery** (Forgot/Reset Password)
- **Redis Integration** for session/token management
- **Security** (Helmet, CORS, Cookie Parser)

## 🛠️ Prerequisites

- [Node.js](https://nodejs.org/) (v16+ recommended)
- [MongoDB](https://www.mongodb.com/)
- [Redis](https://redis.io/)

## 📦 Installation

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd NodeJS/auth
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory and add the following:

   ```env
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/your_db_name

   # Redis Configuration
   REDIS_URL=redis://localhost:6379
   # OR use individual host/port
   # REDIS_HOST=localhost
   # REDIS_PORT=6379
   # REDIS_PASSWORD=your_redis_password

   # JWT Secrets
   JWT_SECRET=your_super_secret_jwt_key

   # Email Service (for password reset)
   EMAIL_USER=your_email@example.com
   EMAIL_PASS=your_email_password

   # Frontend URLs (for email links)
   FRONTEND_URL=http://localhost:5173
   FRONTEND_VERIFY_EMAIL_URL=http://localhost:5173/verify-email
   FRONTEND_FORGOT_PASS_URL=http://localhost:5173/reset-password
   ```

## 🏃‍♂️ Usage

**Start the development server:**

```bash
node index.js
# OR if you have nodemon installed
npx nodemon index.js
```

The server will run on `http://localhost:3000` (or your defined PORT).

## 📡 API Endpoints

Base URL: `/api/auth`

| Method | Endpoint           | Description                                 | Auth Required |
| :----- | :----------------- | :------------------------------------------ | :------------ |
| `POST` | `/register`        | Register a new user account                 | No            |
| `POST` | `/login`           | Log in and receive access/refresh tokens    | No            |
| `POST` | `/refresh`         | Refresh an expired access token             | No            |
| `POST` | `/logout`          | Log out current session (invalidates token) | Yes           |
| `POST` | `/logout-all`      | Log out from all devices                    | Yes           |
| `POST` | `/forgot-password` | Request a password reset email              | No            |
| `POST` | `/reset-password`  | Reset password using token                  | No            |

### Example Header for Authenticated Routes

For routes requiring authentication (like `logout`), you must include the access token in the headers or cookies (depending on your specific `extractToken` middleware implementation, typically headers).

```http
Authorization: Bearer <your_access_token>
```

## 📂 Project Structure

```
.
├── auth/
│   ├── auth.controller.js  # Request handlers
│   ├── auth.routes.js      # Route definitions
│   ├── models/             # Mongoose schemas
│   ├── repositories/       # Data access layer
│   └── services/           # Business logic
├── config/
│   ├── env.js              # Environment config loader
│   └── ...
├── middleware/             # Custom middleware (Token extraction, etc.)
├── utils/                  # Helper functions
├── index.js                # Application entry point
├── package.json
├── .env
└── README.md
```

## 📄 License

[ISC](https://opensource.org/licenses/ISC)
