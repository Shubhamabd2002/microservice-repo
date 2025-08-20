import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prometheus from 'prom-client';
import { AuthRequestDTO, AuthRequestSchema, RefreshRequestSchema, RegisterRequestSchema, TokenResponseDTO, TokenResponseSchema } from "./auth.schema";
import z from 'zod';

interface User {
  id: number;
  username: string;
  password: string;
}

interface AuthRequest extends Request {
  userId?: number;
}

interface RegisterRequestBody {
  username: string;
  password: string;
}

interface LoginRequestBody {
  username: string;
  password: string;
}

interface JwtPayload {
  userId: number;
}
interface ErrorResponse { error: any };

// Create a custom registry
const register = new prometheus.Registry();

// Collect default metrics with proper configuration
prometheus.collectDefaultMetrics({
  register,
  prefix: 'auth_service_',
  labels: { service: 'auth-service' },
  gcDurationBuckets: [0.1, 1, 2, 5] // GC duration buckets
});

// HTTP request duration histogram
const httpRequestDurationMicroseconds = new prometheus.Histogram({
  name: 'auth_service_http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.1, 5, 15, 50, 100, 300, 500, 1000, 3000, 5000],
  registers: [register]
});

// Active users gauge
const activeUsersGauge = new prometheus.Gauge({
  name: 'auth_service_active_users_count',
  help: 'Number of active users in the system',
  registers: [register]
});

// Database query duration histogram
const dbQueryDuration = new prometheus.Histogram({
  name: 'auth_service_db_query_duration_ms',
  help: 'Duration of database queries in ms',
  labelNames: ['query', 'success'],
  buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000],
  registers: [register]
});

const app = express();
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : undefined,
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Metrics endpoint
app.get('/metrics', async (req: Request, res: Response) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    res.status(500).end('Error generating metrics');
  }
});

// Metrics middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const end = httpRequestDurationMicroseconds.startTimer();
  const originalEnd = res.end;
  
  res.end = (...args: any) => {
    end({ 
      method: req.method, 
      route: req.route?.path || req.path, 
      code: res.statusCode 
    });
    return originalEnd.apply(res, args);
  };
  next();
});

// Helper function for instrumented database queries
async function instrumentedQuery<T>(queryText: string, values?: any[]) {
  const end = dbQueryDuration.startTimer();
  try {
    const result = await pool.query<any>(queryText, values);
    end({ query: queryText.split(' ')[0].toUpperCase(), success: 'true' });
    return result;
  } catch (err) {
    end({ query: queryText.split(' ')[0].toUpperCase(), success: 'false' });
    throw err;
  }
}

// Register endpoint
app.post('/register', async (req: any, res: any) => {
  const parsed = RegisterRequestSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error });
  }

  const { username, password } = parsed.data;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await instrumentedQuery<User>(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    
    activeUsersGauge.inc();
    res.status(201).json(result.rows[0]);
  } catch (err: unknown) {
    if (err instanceof Error) {
      if (err.message.includes('duplicate key')) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      console.error('Registration error:', err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});


// Login endpoint
app.post(
  "/login",
  async (
    req: Request<{}, {}, AuthRequestDTO>,
    res: Response<TokenResponseDTO | ErrorResponse>
  ) => {
    try {
      // ✅ Validate body with zod
      const parseResult = AuthRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        // New recommended way: return errors directly or use zod-error utils
        return res.status(400).json({
          error: parseResult.error,
        });
      }

      const { username, password } = parseResult.data;

      // ✅ Check user in DB
      const user = await instrumentedQuery<User>(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );

      if (user.rows.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const isValid = await bcrypt.compare(password, user.rows[0].password);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // ✅ Generate tokens
      const accessToken = jwt.sign(
        { userId: user.rows[0].id },
        JWT_SECRET,
        { expiresIn: "15m" }
      );
      const refreshToken = jwt.sign(
        { userId: user.rows[0].id },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      // ✅ Validate response before sending
      const validatedResponse = TokenResponseSchema.parse({
        accessToken,
        refreshToken,
      });

      return res.json(validatedResponse);
    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Login failed" });
    }
  }
);

app.post('/refresh', (req: Request, res: Response) => {
  const parseResult = RefreshRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: parseResult.error.message, // <-- array of issues
    });
  }

  const { refreshToken } = parseResult.data;

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET) as JwtPayload;

    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Authentication middleware
const authenticate = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'UP' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});