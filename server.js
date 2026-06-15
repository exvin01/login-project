const express = require('express');
const path = require('path');
const {MongoClient} = require('mongodb');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {error: 'Too many attempts. Wait 15 minutes.'},
    keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip
});

const uri = process.env.MONGODB_URI;
let client;
let db;

async function connectDB() {
    if(!db) {
        client = new MongoClient(uri);
        await client.connect();
        db = client.db('CLIENTDB'); // COLLECTION WILL BE INSIDE THIS DATABASE
        console.log('Connected to MongoDB');
    }
    return db;   
}

// SIGNUP with password hashing
app.post('/signup', authLimiter, async (req, res) =>{
    try {
        const {stdnumber, stdpass} = req.body;
        
        if(!stdnumber || !stdpass) {
            return res.status(400).send('Student number and password required');
        }
        if(stdpass.length < 6) {
            return res.status(400).send('Password must be at least 6 characters');
        }

        const database = await connectDB();
        const collection = database.collection('clientdata');

        const userExist = await collection.findOne({stdnumber});
        if(userExist){
            return res.status(400).send('User already exists. Please login.');
        }

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(stdpass, 10);

        await collection.insertOne({
            stdnumber,
            stdpass: hashedPassword, // store hash, not plain text
            createdAt: new Date().toLocaleString('en-CA', {timeZone: 'Africa/Blantyre'}),
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
        });
       
        res.status(201).send('Signup successful ✅ Please go to login page');
    } catch (err) {
        console.error(err); 
        res.status(500).send('Error: signup failed');
    }
});

// LOGIN with password compare
app.post('/login', authLimiter, async (req, res) =>{
    try {
        const {stdnumber, stdpass} = req.body;
        
        if(!stdnumber || !stdpass) {
            return res.status(400).send('Student number and password required');
        }

        const database = await connectDB();
        const collection = database.collection('clientdata');

        // Find user by student number only
        const user = await collection.findOne({stdnumber});
        
        if(!user) {
            return res.status(401).send('Wrong credentials. Please try again.');
        }

        // Compare entered password with hash in DB
        const isMatch = await bcrypt.compare(stdpass, user.stdpass);
        
        if(!isMatch) {
            return res.status(401).send('Wrong credentials. Please try again.');
        } else {
            res.sendFile(path.join(__dirname, 'homepage.html'));
        }
    } catch (err) {
        console.error(err); 
        res.status(500).send('Error: login failed');
    }
});

app.get('/', (req, res) =>{
    res.sendFile(path.join(__dirname, 'index.htm'));
});

app.get('/signup', (req, res) =>{
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/login', (req, res) =>{
    res.sendFile(path.join(__dirname, 'login.html'));
});

module.exports = app;
