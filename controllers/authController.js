const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;

// Моковая база данных (замените на реальную БД)
let users = [];
let refreshTokens = [];

const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Проверка существования пользователя
    if (users.some((u) => u.email === email)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
    };

    users.push(user);

    // Генерация токенов
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Registration failed' });
  }
};

function generateAccessToken(user) {
  return jwt.sign({ userId: user.id, email: user.email }, ACCESS_TOKEN_SECRET, {
    expiresIn: '15m',
  });
}

function generateRefreshToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' },
  );
}

module.exports = { register };
