const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
app.use(express.json());

// INSECURE JWT Configuration (for testing only!)
const JWT_SECRET = '123456789';
const JWT_EXPIRY = 120; // 2 minutes in seconds
const PORT = 3000;

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Dummy API with Insecure JWT',
      version: '1.0.0',
      description: 'A dummy API with intentionally insecure JWT for testing purposes. ⚠️ WARNING: Contains extensive PII in JWT tokens!',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter the JWT token obtained from /auth endpoint',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ['./server.js'], // Path to the API routes
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get('/', (req, res) => {
  res.redirect('/api-docs');
});

// Dummy user database with extensive PII
const users = {
  'alice': {
    password: 'password123',
    user_id: '987654321',
    name: 'Alice Robertson',
    email: 'alice.robertson@example.com',
    ssn: '987-65-4321',
    credit_card: '4111-1111-1111-1111',
    phone: '+1-555-123-4567',
    address: '456 Main St, Springfield, USA',
    dob: '1985-03-12',
    role: 'admin',
    drivers_license: 'DL-123456789',
    passport: 'P-987654321',
    bank_account: '1234567890',
    medical_id: 'MED-2023-456',
    tax_id: 'TIN-98-7654321'
  },
  'bob': {
    password: 'secret456',
    user_id: '123456789',
    name: 'Bob Johnson',
    email: 'bob.johnson@example.com',
    ssn: '123-45-6789',
    credit_card: '5555-4444-3333-2222',
    phone: '+1-555-987-6543',
    address: '789 Oak Ave, Portland, USA',
    dob: '1990-07-25',
    role: 'user',
    drivers_license: 'DL-987654321',
    passport: 'P-123456789',
    bank_account: '0987654321',
    medical_id: 'MED-2023-789',
    tax_id: 'TIN-12-3456789'
  }
};

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Unauthorized: Token expired' });
      }
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
    req.user = user;
    next();
  });
};

/**
 * @swagger
 * /auth:
 *   post:
 *     summary: Login and get JWT token
 *     description: Authenticate with username and password to receive an insecure JWT token containing extensive PII
 *     tags: [Authentication]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: alice
 *                 description: Use 'alice' or 'bob' for testing
 *               password:
 *                 type: string
 *                 example: password123
 *                 description: Use 'password123' for alice, 'secret456' for bob
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token with extensive PII
 *                 expires_in:
 *                   type: number
 *                   example: 120
 *                 token_type:
 *                   type: string
 *                   example: Bearer
 *                 user_info:
 *                   type: object
 *                   properties:
 *                     username:
 *                       type: string
 *                     name:
 *                       type: string
 *                     role:
 *                       type: string
 *       400:
 *         description: Missing username or password
 *       401:
 *         description: Invalid credentials
 */
app.post('/auth', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create JWT with extensive PII (INSECURE - for testing only!)
  const tokenPayload = {
    sub: user.user_id,
    user_id: user.user_id,
    name: user.name,
    email: user.email,
    ssn: user.ssn,
    credit_card: user.credit_card,
    phone: user.phone,
    address: user.address,
    dob: user.dob,
    role: user.role,
    drivers_license: user.drivers_license,
    passport: user.passport,
    bank_account: user.bank_account,
    medical_id: user.medical_id,
    tax_id: user.tax_id,
    login_time: new Date().toISOString(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + JWT_EXPIRY
  };

  const token = jwt.sign(tokenPayload, JWT_SECRET, { algorithm: 'HS256' });

  res.json({
    token,
    expires_in: JWT_EXPIRY,
    token_type: 'Bearer',
    user_info: {
      username,
      name: user.name,
      role: user.role
    }
  });
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get list of users
 *     description: Returns a list of dummy users with basic information
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: number
 *                       name:
 *                         type: string
 *                       email:
 *                         type: string
 *                       department:
 *                         type: string
 *                 total:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/users', authenticateToken, (req, res) => {
  const userList = [
    { id: 1, name: 'John Doe', email: 'john@example.com', department: 'Engineering' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com', department: 'Marketing' },
    { id: 3, name: 'Mike Johnson', email: 'mike@example.com', department: 'Sales' },
    { id: 4, name: 'Sarah Williams', email: 'sarah@example.com', department: 'HR' },
    { id: 5, name: 'Tom Brown', email: 'tom@example.com', department: 'Finance' }
  ];
  res.json({ users: userList, total: userList.length });
});

/**
 * @swagger
 * /stats:
 *   get:
 *     summary: Get system statistics
 *     description: Returns system and API performance metrics
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 system:
 *                   type: object
 *                   properties:
 *                     uptime:
 *                       type: number
 *                     memory_usage:
 *                       type: object
 *                     cpu_usage:
 *                       type: number
 *                     active_connections:
 *                       type: number
 *                 api:
 *                   type: object
 *                   properties:
 *                     requests_today:
 *                       type: number
 *                     errors_today:
 *                       type: number
 *                     average_response_time:
 *                       type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/stats', authenticateToken, (req, res) => {
  res.json({
    system: {
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      cpu_usage: Math.random() * 100,
      active_connections: Math.floor(Math.random() * 1000) + 100
    },
    api: {
      requests_today: Math.floor(Math.random() * 10000) + 5000,
      errors_today: Math.floor(Math.random() * 100),
      average_response_time: Math.random() * 200 + 50
    }
  });
});

/**
 * @swagger
 * /submit-data:
 *   post:
 *     summary: Submit data
 *     description: Submit data to the API for processing
 *     tags: [Data]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - data
 *             properties:
 *               data:
 *                 type: object
 *                 example: { "key": "value", "test": 123 }
 *                 description: Any data object to submit
 *     responses:
 *       200:
 *         description: Data submitted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 id:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                 processed_by:
 *                   type: string
 *                 data_received:
 *                   type: object
 *       400:
 *         description: Bad request - Missing data field
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.post('/submit-data', authenticateToken, (req, res) => {
  const { data } = req.body;
  
  if (!data) {
    return res.status(400).json({ error: 'Data field is required' });
  }

  res.json({
    success: true,
    id: crypto.randomBytes(16).toString('hex'),
    timestamp: new Date().toISOString(),
    processed_by: req.user.name,
    data_received: data
  });
});

/**
 * @swagger
 * /devices:
 *   get:
 *     summary: Get list of devices
 *     description: Returns a list of IoT devices with their status
 *     tags: [Devices]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Device list retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 devices:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       type:
 *                         type: string
 *                         enum: [sensor, gateway, controller]
 *                       status:
 *                         type: string
 *                         enum: [online, offline, maintenance]
 *                       last_seen:
 *                         type: string
 *                       battery:
 *                         type: number
 *                       firmware:
 *                         type: string
 *                 total:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/devices', authenticateToken, (req, res) => {
  const devices = [];
  for (let i = 1; i <= 10; i++) {
    devices.push({
      id: `DEV-${String(i).padStart(4, '0')}`,
      name: `Device ${i}`,
      type: ['sensor', 'gateway', 'controller'][Math.floor(Math.random() * 3)],
      status: ['online', 'offline', 'maintenance'][Math.floor(Math.random() * 3)],
      last_seen: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      battery: Math.floor(Math.random() * 100),
      firmware: `v${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 20)}`
    });
  }
  res.json({ devices, total: devices.length });
});

/**
 * @swagger
 * /alerts:
 *   get:
 *     summary: Get active alerts
 *     description: Returns a list of active system alerts
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Alerts retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 alerts:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       type:
 *                         type: string
 *                         enum: [critical, warning, info]
 *                       message:
 *                         type: string
 *                       source:
 *                         type: string
 *                       timestamp:
 *                         type: string
 *                       acknowledged:
 *                         type: boolean
 *                 unacknowledged:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/alerts', authenticateToken, (req, res) => {
  const alertTypes = ['critical', 'warning', 'info'];
  const alerts = [];
  
  for (let i = 1; i <= 5; i++) {
    alerts.push({
      id: crypto.randomBytes(8).toString('hex'),
      type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
      message: `Alert message ${i}: System event detected`,
      source: `System-${Math.floor(Math.random() * 5) + 1}`,
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      acknowledged: Math.random() > 0.5
    });
  }
  
  res.json({ alerts, unacknowledged: alerts.filter(a => !a.acknowledged).length });
});

/**
 * @swagger
 * /weather:
 *   get:
 *     summary: Get weather data
 *     description: Returns weather information for multiple cities
 *     tags: [Data]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Weather data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 weather:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       city:
 *                         type: string
 *                       temperature:
 *                         type: number
 *                       humidity:
 *                         type: number
 *                       condition:
 *                         type: string
 *                       wind_speed:
 *                         type: number
 *                       updated_at:
 *                         type: string
 *                 locations:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/weather', authenticateToken, (req, res) => {
  const cities = ['New York', 'London', 'Tokyo', 'Sydney', 'Paris'];
  const conditions = ['Sunny', 'Cloudy', 'Rainy', 'Partly Cloudy', 'Stormy'];
  
  const weather = cities.map(city => ({
    city,
    temperature: Math.floor(Math.random() * 30) + 10,
    humidity: Math.floor(Math.random() * 60) + 40,
    condition: conditions[Math.floor(Math.random() * conditions.length)],
    wind_speed: Math.floor(Math.random() * 20) + 5,
    updated_at: new Date().toISOString()
  }));
  
  res.json({ weather, locations: weather.length });
});

/**
 * @swagger
 * /log:
 *   post:
 *     summary: Log events
 *     description: Submit log entries to the system
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - level
 *               - message
 *             properties:
 *               level:
 *                 type: string
 *                 enum: [debug, info, warning, error, critical]
 *                 example: info
 *               message:
 *                 type: string
 *                 example: User action completed successfully
 *               context:
 *                 type: object
 *                 example: { "user_id": "123", "action": "login" }
 *     responses:
 *       200:
 *         description: Log entry created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 log_id:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                 level:
 *                   type: string
 *                 message:
 *                   type: string
 *                 context:
 *                   type: object
 *                 logged_by:
 *                   type: string
 *       400:
 *         description: Bad request - Missing or invalid fields
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.post('/log', authenticateToken, (req, res) => {
  const { level, message, context } = req.body;
  
  if (!level || !message) {
    return res.status(400).json({ error: 'Level and message are required' });
  }
  
  const validLevels = ['debug', 'info', 'warning', 'error', 'critical'];
  if (!validLevels.includes(level)) {
    return res.status(400).json({ error: 'Invalid log level' });
  }
  
  res.json({
    success: true,
    log_id: crypto.randomBytes(12).toString('hex'),
    timestamp: new Date().toISOString(),
    level,
    message,
    context,
    logged_by: req.user.name
  });
});

/**
 * @swagger
 * /products:
 *   get:
 *     summary: Get product catalog
 *     description: Returns a list of products with pricing and availability
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Product list retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 products:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       category:
 *                         type: string
 *                       price:
 *                         type: string
 *                       stock:
 *                         type: number
 *                       rating:
 *                         type: string
 *                       available:
 *                         type: boolean
 *                 total:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/products', authenticateToken, (req, res) => {
  const categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Sports'];
  const products = [];
  
  for (let i = 1; i <= 20; i++) {
    products.push({
      id: `PROD-${String(i).padStart(5, '0')}`,
      name: `Product ${i}`,
      category: categories[Math.floor(Math.random() * categories.length)],
      price: (Math.random() * 500 + 10).toFixed(2),
      stock: Math.floor(Math.random() * 100),
      rating: (Math.random() * 2 + 3).toFixed(1),
      available: Math.random() > 0.2
    });
  }
  
  res.json({ products, total: products.length });
});

/**
 * @swagger
 * /orders:
 *   get:
 *     summary: Get order history
 *     description: Returns order history for the authenticated user
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Order list retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 orders:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       customer:
 *                         type: string
 *                       status:
 *                         type: string
 *                         enum: [pending, processing, shipped, delivered, cancelled]
 *                       total:
 *                         type: string
 *                       items:
 *                         type: number
 *                       created_at:
 *                         type: string
 *                       shipping_address:
 *                         type: string
 *                 total:
 *                   type: number
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
app.get('/orders', authenticateToken, (req, res) => {
  const statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
  const orders = [];
  
  for (let i = 1; i <= 15; i++) {
    const itemCount = Math.floor(Math.random() * 5) + 1;
    orders.push({
      id: `ORD-${String(Date.now() + i).slice(-8)}`,
      customer: req.user.name,
      status: statuses[Math.floor(Math.random() * statuses.length)],
      total: (Math.random() * 1000 + 50).toFixed(2),
      items: itemCount,
      created_at: new Date(Date.now() - Math.random() * 30 * 24 * 3600000).toISOString(),
      shipping_address: req.user.address || '123 Default St, City, Country'
    });
  }
  
  res.json({ orders, total: orders.length });
});

// Default error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Dummy API server running on http://localhost:${PORT}`);
  console.log(`Swagger UI available at http://localhost:${PORT}/api-docs`);
  console.log('\nAvailable endpoints:');
  console.log('POST /auth - Login (username: alice, password: password123)');
  console.log('GET  /users - Get users list (requires auth)');
  console.log('GET  /stats - Get system statistics (requires auth)');
  console.log('POST /submit-data - Submit data (requires auth)');
  console.log('GET  /devices - Get devices list (requires auth)');
  console.log('GET  /alerts - Get active alerts (requires auth)');
  console.log('GET  /weather - Get weather data (requires auth)');
  console.log('POST /log - Log events (requires auth)');
  console.log('GET  /products - Get products catalog (requires auth)');
  console.log('GET  /orders - Get order history (requires auth)');
  console.log('\nWARNING: This API uses an INSECURE JWT implementation with extensive PII!');
  console.log('JWT Secret: 123456789 (INSECURE - FOR TESTING ONLY!)');
});
