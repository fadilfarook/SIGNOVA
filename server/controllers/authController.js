const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/user');

const makeToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });

const userData = (user) => ({
  id: user._id,
  username: user.username,
  email: user.email,
});

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }

  const { username, email, password } = req.body;

  const exists = await User.findOne({ $or: [{ email }, { username }] });
  if (exists) {
    return res.status(400).json({ message: 'Username or email already in use' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ username, email, password: hashed });

  res.status(201).json({ token: makeToken(user._id), user: userData(user) });
};

exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }

  const { email, password } = req.body;

  const user = await User.findOne({ email }).select('+password');
  const match = user && (await bcrypt.compare(password, user.password));
  if (!match) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  res.json({ token: makeToken(user._id), user: userData(user) });
};