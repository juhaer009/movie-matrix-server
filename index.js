const express = require('express')
const cors = require("cors")
const app = express()
require('dotenv').config()
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const port = process.env.PORT || 5000

//middleware
app.use(express.json())

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:5173'];

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
}))

// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@movie-matrix-cluster.hfigrlp.mongodb.net/?appName=movie-matrix-cluster`;
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@movie-matrix-cluster.kyhktuc.mongodb.net/?appName=movie-matrix-cluster`;
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@movie-matrix-cluster.kyhktuc.mongodb.net/?appName=movie-matrix-cluster`;

console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASS:', process.env.DB_PASS ? '***' : 'undefined');
console.log('Connection URI:', uri.replace(process.env.DB_PASS || '', '***'));

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    await client.connect();

    const userCollection = client.db("movie-matrix").collection("users");
    const movieCollection = client.db("movie-matrix").collection("movies")

    app.post('/api/users/register', async (req, res) => {
      try {
        const { name, role, email, password } = req.body;

        if (!name || !role || !email || !password) {
          return res.status(400).json({ message: 'name, role, email and password are required' });
        }

        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: 'User already exists with this email' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userDoc = {
          name,
          role,
          email,
          password: hashedPassword,
          createdAt: new Date()
        };

        const result = await userCollection.insertOne(userDoc);

        if (!process.env.JWT_SECRET) {
          console.error('JWT_SECRET is not set in environment variables. Cannot create JWT token.');
          return res.status(500).json({ message: 'Server configuration error' });
        }

        const tokenPayload = { name, role, email };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(201).json({
          message: 'User registered successfully',
          userId: result.insertedId,
          token
        });
      } catch (error) {
        console.error('Error in /api/users/register:', error);
        return res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.post('/api/users/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).json({ message: 'email and password are required' });
        }

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ message: 'Invalid email or password' });
        }

        if (!process.env.JWT_SECRET) {
          console.error('JWT_SECRET is not set in environment variables. Cannot create JWT token.');
          return res.status(500).json({ message: 'Server configuration error' });
        }

        const tokenPayload = {
          name: user.name,
          role: user.role,
          email: user.email
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({
          message: 'Login successful',
          token
        });
      } catch (error) {
        console.error('Error in /api/users/login:', error);
        return res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.get('/movies', async (req, res) => {
      try {
        const result = await movieCollection.find().toArray();
        res.send(result)
      } catch (error) {
        console.error('Error in /movies:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    })

    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
    
    // Start server after DB connection and routes are set up
    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`)
    })
  } finally {
  }
}

app.get('/', (req, res) => {
  res.send('movie matrix server is running')
})

run().catch(console.dir);