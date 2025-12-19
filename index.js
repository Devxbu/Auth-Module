const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const helmet = require("helmet");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const authRoutes = require("./auth/auth.routes");
const env = require("./config/env");
const app = express();

// Middleware
app.use(express.json());
app.use(morgan("dev"));
app.use(cors());
app.use(helmet());
app.use(cookieParser());

// MongoDB connection
mongoose
  .connect(env.mongoUri)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// Routes
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.use("/api/auth", authRoutes);

// Start server
const PORT = env.port || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
