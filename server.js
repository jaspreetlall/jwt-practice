const { response } = require('express');
const express = require('express');
const bcrypt = require('bcrypt'); // for encrypting
const jwt = require('jsonwebtoken'); // for hashing and sigining the tokens
const dotenv = require('dotenv'); // for importing environment variables
const app = express();

app.use(express.json());
dotenv.config();

const users = [
  {
    name: 'Jaspreet',
    password: '$2b$10$JE880ztSEmdfXhbvoDX1A.r5iUgzO/KTYDpbnYGU7mO7e.RYA8uDy'
  }
];

const posts = [
  {
    username: 'Jaspreet',
    title: 'First post'
  },
  {
    username: 'Harpreet',
    title: 'Second post'
  }
]

let refreshTokens = [];

// Middleware funtion to authenticate token
// Always takes 3 arguments req, res, and next
// next() moves on to next steps/middlewares
// Use this function on the routes that needs protection
function authenticateToken(req, res, next) {
  // Getting the authorization headers from req.headers
  // authHeader looks like this, assuming it to be the type of "Bearer"
  // Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  const authHeader = req.headers.authorization;
  // Extracting token from the authHeader
  // We split the string from authHeader at the space after 'Bearer'
  // into an array and using the 2nd element of the array
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).send("You don't have access");
  // Once the token's existence is checked, it can be verified
  // using JWT. jwt.verify takes the following arguments
  // 1 => token to be verified
  // 2 => the TOKEN SECRET that is used to HASH(serialize) the token by server
  // 3 => callback with error and the value that was hashed(serialized)
  // which in our code is the user object.
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).send("Expired token");
    // If the verification passes, we set req.user equal to
    // the user returned from the token
    req.user = user;
    next();
  })
}

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s'});
}

app.get('/posts', authenticateToken, (req, res) => {
  console.log(req.user);
  console.log(req.user.name);
  res.json(posts.filter(post => post.username === req.user.name));
})

app.post('/signup', async (req, res) => {
  try {
    // 10 is the default number of rounds for hash salt in bcrypt
    // higher values result in slower process but stronger encryption
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { name: req.body.name, password: hashedPassword }
    users.push(user);
    res.status(201).send("User created " + hashedPassword);
  } catch {
    res.status(500).send();
  }
})

app.post('/login', async (req, res) => {
  const user = users.find(user => user.name = req.body.name);
  if (user === null) {
    return res.status(400).send('Cannot find user');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const user = { name: req.body.name};
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      res.json({
        accessToken: accessToken,
        refreshToken: refreshToken
      });
    } else {
      res.send('Login Failed. Invalid username or password');
    }
  }
  catch {
    res.status(500).send();
  }
})

app.post('/token', (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.status(401);
  if (!refreshTokens.includes(refreshToken)) return res.status(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  })
})

app.delete('/logout', (req, res) => {
  console.log("token", req.body.token);
  console.log("Before Filter ", refreshTokens);
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  console.log("After Filter", refreshTokens);
  res.sendStatus(204); // Delete success
})

app.listen(3000);