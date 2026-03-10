const express = require("express");
const cors = require("cors");
const app = express();

require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const port = process.env.PORT || 5000;

//middleware
app.use(express.json());

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
  : ["http://localhost:3000"];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  }),
);

// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@movie-matrix-cluster.kyhktuc.mongodb.net/?appName=movie-matrix-cluster`;
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@simple-crud-server.hfigrlp.mongodb.net/?appName=simple-crud-server`;
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ekpzegp.mongodb.net/?appName=Cluster0";

const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    await client.connect();

    const userCollection = client.db("movie-matrix").collection("users");
    const movieCollection = client.db("movie-matrix").collection("movies");

    // JWT Verification Middleware
    const verifyToken = (req, res, next) => {
      const token = req.cookies?.auth_token || req.headers.authorization?.split(" ")[1];

      if (!token) {
        return res.status(401).send({ message: "Unauthorized: No token provided" });
      }

      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "Unauthorized: Invalid token" });
        }
        req.decoded_email = decoded.email;
        req.decoded_role = decoded.role;
        next();
      });
    };

    // Admin Verification
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      if (!email) {
        return res.status(401).send({ message: "Unauthorized" });
      }
      const user = await userCollection.findOne({ email });
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Forbidden: Admin access required" });
      }
      next();
    };

    app.post("/api/users/register", async (req, res) => {
      try {
        const { name, role, email, password, photoURL } = req.body;

        if (!name || !role || !email || !password) {
          return res
            .status(400)
            .json({ message: "name, role, email and password are required" });
        }

        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res
            .status(409)
            .json({ message: "User already exists with this email" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userDoc = {
          name,
          role,
          email,
          password: hashedPassword,
          photoURL: photoURL || "",
          createdAt: new Date(),
        };

        const result = await userCollection.insertOne(userDoc);

        if (!process.env.JWT_SECRET) {
          console.error(
            "JWT_SECRET is not set in environment variables. Cannot create JWT token.",
          );
          return res
            .status(500)
            .json({ message: "Server configuration error" });
        }

        const tokenPayload = { name, role, email };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });

        res.cookie("auth_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(201).json({
          message: "User registered successfully",
          userId: result.insertedId,
          user: { name, role, email, photoURL },
          token,
        });
      } catch (error) {
        console.error("Error in /api/users/register:", error);
        return res.status(500).json({ message: "Internal server error" });
      }
    });

    // Get current user profile
    app.get("/api/users/profile", verifyToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email }, { projection: { password: 0 } });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        res.json(user);
      } catch (error) {
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Update user profile
    app.patch("/api/users/profile", verifyToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const { name, photoURL } = req.body;
        const updateDoc = {};
        if (name) updateDoc.name = name;
        if (photoURL) updateDoc.photoURL = photoURL;

        const result = await userCollection.updateOne(
          { email },
          { $set: updateDoc }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Profile updated successfully" });
      } catch (error) {
        res.status(500).json({ message: "Internal server error" });
      }
    });


    app.post("/api/users/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res
            .status(400)
            .json({ message: "email and password are required" });
        }

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        if (!process.env.JWT_SECRET) {
          console.error(
            "JWT_SECRET is not set in environment variables. Cannot create JWT token.",
          );
          return res
            .status(500)
            .json({ message: "Server configuration error" });
        }

        const tokenPayload = {
          name: user.name,
          role: user.role,
          email: user.email,
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });

        res.cookie("auth_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({
          message: "Login successful",
          token,
        });
      } catch (error) {
        console.error("Error in /api/users/login:", error);
        return res.status(500).json({ message: "Internal server error" });
      }
    });

    //add movies
    app.post("/app/addMovies", async (req, res) => {
      try {
        const {
          title,
          description,
          image,
          email,
          duration,
          price,
          genre,
          imdbRating,
        } = req.body;

        if (!title || !description || !image) {
          return res.status(400).json({ message: "Required fields missing" });
        }
        console.log(req.body);

        const result = await movieCollection.insertOne({
          title,
          description,
          image,
          email,
          duration,
          price,
          genre,
          imdbRating,
          createdAt: new Date(),
        });

        res.status(201).json(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.delete("/movies/:id", async (req, res) => {
      const id = req.params.id;
      const result = await movieCollection.deleteOne({
        _id: new ObjectId(id),
      });

      if (result.deletedCount === 1) {
        res.send({ success: true, message: "Movie deleted successfully" });
      } else {
        res.status(500).send({ success: false, error: error.message });
      }
    });

    app.get("/movies", async (req, res) => {
      try {
        const result = await movieCollection.find().toArray();
        res.send(result);
      } catch (error) {
        console.error("Error in /movies:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.patch("/api/movies/:id/watchlist", async (req, res) => {
      try {
        const { id } = req.params;
        const { watchlistStatus } = req.body;

        if (typeof watchlistStatus !== "boolean") {
          return res
            .status(400)
            .json({ message: "watchlistStatus must be a boolean value" });
        }

        const { ObjectId } = require("mongodb");

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid movie ID" });
        }

        const result = await movieCollection.findOneAndUpdate(
          { _id: new ObjectId(id) },
          { $set: { watchlistStatus } },
          { returnDocument: "after" },
        );

        if (!result) {
          return res.status(404).json({ message: "Movie not found" });
        }

        res.json({
          message: "Watchlist status updated successfully",
          movie: result,
        });
      } catch (error) {
        console.error("Error in /api/movies/:id/watchlist:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("movie matrix server is running");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});