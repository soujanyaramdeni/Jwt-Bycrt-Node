
const express = require('express');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs=require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key';


app.use(express.json());

const users = []; 


app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    
    if (users.some((user) => user.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    const Password = (req.body && req.body.password) ? req.body.password.trim() : '';
     const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = {
      username,
      password: hashedPassword,
    };
    users.push(user);
    fs.writeFile("./index.js",JSON.stringify(user),(error)=>{
    res.json({ message: 'User registered successfully' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    
    const user = users.find((user) => user.username === username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

  
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully' });
});


function verifyToken(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - Token not provided' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }

    req.user = decoded;
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});