const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');
const crypto = require('crypto');
const uuid = require('uuid');
const db = new sqlite3.Database('totally_not_my_privateKeys.db');
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const port = 8080;
let keyPair;
let expiredKeyPair;
let token;
let expiredToken;


async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}


function createTable(){
   db.run(`CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL)`);
   db.run(`CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email TEXT UNIQUE,
      date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP
   )`);
   db.run(`CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id))`);
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };
  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  db.all(`SELECT * FROM keys`,async(err, rows) => {
    if (err) {
      res.json({"err":err});
    } else {
      var data=rows;
      var data_list=[];
      for(var i=0;i<data.length;i++){
        let jwkKey = await jose.JWK.asKey(data[i].key, 'pem');
        const validKeys = [jwkKey].filter(key => !key.expired);
        if(data[i].exp>Math.floor(Date.now() / 1000)){
          data_list.push({"keys": validKeys.map(key => key.toJSON()) })
        }
      }
      res.json({"data_list":data_list});
    }
  })
});

app.post('/auth',async (req, res) => {
  try {
    const ip = req.ip;
    const timestamp = new Date().toISOString();
    const { username } = req.body;
    const selectQuery = 'SELECT id FROM users WHERE username = ?';
    try {
      var id = await new Promise((resolve, reject) => {
        db.get(selectQuery, [username], (error, row) => {
          if (error) {
            reject(error);
          } else {
            resolve(row ? row.id : null);
          }
        });
      });

      if (!id) {
        res.status(404).send('No information can be found for this user name.');
        return;
      }
      const insert_query = 'INSERT INTO auth_logs(request_ip, request_timestamp, user_id) VALUES (?, ?, ?)';
      db.run(insert_query, [ip, timestamp, id], (error) => {
        if (error) {
          res.status(500).send('Internal Server Add Error');
        }
      });

      if (req.query.expired === 'true') {
        res.send(expiredToken);
      } else {
        res.send(token);
      }
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    const generatepassword = uuid.v4();
    try {
      const password_hash = await argon2.hash(generatepassword);
      const add_query = 'INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?)';
      db.run(add_query, [username, email, password_hash], (error) => {
        if (error) {
          console.log(error);
          res.status(400).send(error);
        } else {
          res.status(201).json({"message":"Registered successfully!", password: generatepassword });
        }
      });
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Add Error');
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

generateKeyPairs().then(() => {
  createTable();
  generateExpiredJWT();
  generateToken();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
