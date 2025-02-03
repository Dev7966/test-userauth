const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const cors = require('cors');
app.use(express.json());
const port = 3000;
import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

app.use(cors());

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
const userSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .pattern(/(?=.*[a-z])(?=.*[A-Z])(?=.*\W)/)
    .required(),
});
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  // TODO
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  // TODO
  return Object.values(MEMORY_DB).find((user) => user.email === email);
}

// Request body -> UserDto
app.post('/register', (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)

  const { error, value } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, email, type, password } = value;

  if (getUserByUsername(username)) {
    return res.status(401).json({ error: 'Username already registered' });
  }

  if (getUserByEmail(email)) {
    return res.status(401).json({ error: 'Email already registered' });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordhash = bcrypt.hashSync(password, salt);

  MEMORY_DB[username] = { email, type, salt, passwordhash };
  res.status(200).json({ message: 'User registered successfully' });
});

// Request body -> { username: string, password: string }
app.post('/login', (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  const user = getUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const isPasswordValid = bcrypt.compareSync(password, user.passwordhash);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  res.status(200).json({ message: 'Login successful' });
});

app.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    message: 'server is running',
  });
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
