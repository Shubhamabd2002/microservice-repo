import express, { NextFunction } from "express";
import { Pool } from "pg";
// const bcrypt = require('bcrypt');
import jwt, { JwtPayload } from "jsonwebtoken";
import cors from "cors";
interface CustomJwtPayload extends JwtPayload {
  userId: string; // or number, depending on your implementation
}
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : undefined,
});

// JWT secret (should match auth service)
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Middleware to verify JWT
const authenticate = (req: any, res: any, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as CustomJwtPayload;
    req.userId = decoded.userId; // Now TypeScript knows this exists
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Create payment
app.post("/payments", authenticate, async (req: any, res: any) => {
  try {
    const { amount, description } = req.body;
    const result = await pool.query(
      "INSERT INTO payments (user_id, amount, description) VALUES ($1, $2, $3) RETURNING *",
      [req.userId, amount, description]
    );

    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Get payments
app.get("/payments", authenticate, async (req: any, res: any) => {
  try {
    const result = await pool.query(
      "SELECT * FROM payments WHERE user_id = $1",
      [req.userId]
    );

    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Payment service running on port ${PORT}`);
});
