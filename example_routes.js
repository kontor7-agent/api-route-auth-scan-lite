// Demo file with deliberate gaps. Try:  python route_auth_scan.py example_routes.js
const express = require('express');
const app = express();
const router = express.Router();

app.get('/health', (req, res) => res.json({ ok: true }));        // public by pattern
app.post('/api/auth/login', loginHandler);                        // public by pattern

app.get('/api/orders', requireAuth, listOrders);                  // PROTECTED
app.delete('/api/orders/:id', deleteOrder);                       // MISSING_AUTH (forgot middleware)
app.get('/api/export', (req, res) => res.send('all data'));       // MISSING_AUTH

// noauth-ok
app.get('/api/public-list', listPublic);                          // deliberately public

router.use(authenticate);
router.get('/users', listUsers);                                  // PROTECTED_VIA_USE
