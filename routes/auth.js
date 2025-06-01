const express = require('express');
const router = express.Router();
const { register } = require('../controllers/authController');

// Роут для регистрации
router.post('/register', register);

module.exports = router;
