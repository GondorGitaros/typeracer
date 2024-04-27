// imports
const express = require('express');
const fs = require('fs');
const app = express();
const mysql = require('mysql');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

// configs
const port = 3000;
app.use(express.static('src'));
app.use(bodyParser.json());
dotenv.config();

// connect to database
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// on request: send index.html
app.get('/', (req, res) => {
    fs.readFile('./src/index.html', 'utf8', (error, html) => {
        if (error) {
            console.error('Error loading HTML file:', error);
            res.status(500).send('Error loading HTML file');
        } else {
            res.send(html);
        }
    });
});

// login
app.post('/login', (req, res) => {
    const { usernameOrEmail, password } = req.body;
    // find user
    const query = 'SELECT * FROM User WHERE username = ? OR email = ?';
    connection.query(query, [usernameOrEmail, usernameOrEmail], (error, results) => {
        if (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Internal server error' });
        } else if (results.length > 0) {
            // check password
            bcrypt.compare(password, results[0].password, (error, match) => {
                if (error) {
                    console.error('Bcrypt error:', error);
                    res.status(500).json({ error: 'Internal server error' });
                } else if (match) {
                    const username = results[0].username;
                    const token = jwt.sign({ username: username }, process.env.JWT_SECRET);
                    const queryId = 'SELECT id FROM User WHERE username = ?';
                        connection.query(queryId, [username], (error, results) => {
                            if (error) {
                                console.error('Database error:', error);
                                res.status(500).json({ error: 'Internal server error' });
                            } else {
                                const id = results[0].id;
                                res.json({ token: token , id: id});
                            }
                        });
                } else {
                    res.status(400).json({ error: 'Invalid username or password' });
                }
            });
        } else {
            res.status(400).json({ error: 'Invalid username or password' });
        }
    });
});

// register
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    
    // check if exists
    const queryCheck = 'SELECT * FROM User WHERE username = ? OR email = ?';
    connection.query(queryCheck, [username, email], (error, results) => {
        if (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Internal server error' });
        } else if (results.length > 0) {
            res.status(400).json({ error: 'Username or email already exists' });
        } else {
            // Hash password
            bcrypt.hash(password, 10, (error, hash) => {
                if (error) {
                    console.error('Bcrypt error:', error);
                    res.status(500).json({ error: 'Internal server error' });
                } else {
                    // Insert new user
                    const queryInsert = 'INSERT INTO User (username, email, password) VALUES (?, ?, ?)';
                    connection.query(queryInsert, [username, email, hash], (error, results) => {
                        if (error) {
                            console.error('Database error:', error);
                            res.status(500).json({ error: 'Internal server error' });
                        } else {
                            const token = jwt.sign({ username: username }, process.env.JWT_SECRET);
                            // get id
                            const queryId = 'SELECT id FROM User WHERE username = ?';
                            connection.query(queryId, [username], (error, results) => {
                                if (error) {
                                    console.error('Database error:', error);
                                    res.status(500).json({ error: 'Internal server error' });
                                } else {
                                    const id = results[0].id;
                                    res.json({ token: token , id: id});
                                }
                            });
                        }
                    });
                }
            });
        }
    });
});

// verify
app.post('/verify', (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            res.status(403).json({ error: 'Invalid token' });
        } else {
            res.json({ status: 'success' });
        }
    });
});

// get username

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    connection.query('SELECT username FROM User WHERE id = ?', [userId], (error, results) => {
        if (error) {
            console.error(error); // Log the actual error message
            res.status(500).json({ error: 'An error occurred' });
        } else if (results.length > 0) {
            res.json({ username: results[0].username });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
})

// start server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
