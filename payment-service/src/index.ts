import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import jwt, { JwtPayload } from 'jsonwebtoken';
import prometheus from 'prom-client';

interface Payment {
  id: number;
  user_id: number;
  amount: number;
  description: string;
  created_at: Date;
}

interface CustomJwtPayload extends JwtPayload {
  userId: string;
}

interface AuthRequest extends Request {
  userId?: string;
}

// Create a custom registry
const register = new prometheus.Registry();

// Collect default metrics with proper configuration
prometheus.collectDefaultMetrics({
  register,
  prefix: 'payment_service_',
  labels: { service: 'payment-service' },
  gcDurationBuckets: [0.1, 1, 2, 5]
});

// HTTP request duration histogram
const httpRequestDurationMicroseconds = new prometheus.Histogram({
  name: 'payment_service_http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.1, 5, 15, 50, 100, 300, 500, 1000, 3000, 5000],
  registers: [register]
});

// Payment metrics
const paymentsCounter = new prometheus.Counter({
  name: 'payment_service_payments_created_total',
  help: 'Total number of payments created',
  registers: [register]
});

const paymentAmountGauge = new prometheus.Gauge({
  name: 'payment_service_payment_amounts',
  help: 'Amounts of processed payments',
  labelNames: ['user_id'],
  registers: [register]
});

// Database query duration histogram
const dbQueryDuration = new prometheus.Histogram({
  name: 'payment_service_db_query_duration_ms',
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

// JWT secret (should match auth service)
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

// Middleware to verify JWT
const authenticate = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as CustomJwtPayload;
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Create payment
app.post('/payments', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const { amount, description } = req.body;
    const result = await instrumentedQuery<Payment>(
      'INSERT INTO payments (user_id, amount, description) VALUES ($1, $2, $3) RETURNING *',
      [req.userId, amount, description]
    );
    
    // Update metrics
    paymentsCounter.inc();
    paymentAmountGauge.set({ user_id: req.userId }, amount);
    
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Get payments
app.get('/payments', authenticate, async (req: AuthRequest, res: Response) => {
  try {
    const result = await instrumentedQuery<Payment>(
      'SELECT * FROM payments WHERE user_id = $1',
      [req.userId]
    );
    
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'UP' });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Payment service running on port ${PORT}`);
});