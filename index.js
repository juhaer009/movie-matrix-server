const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();

require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const port = process.env.PORT || 5000;

// ✅ Import Stripe
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cookieParser());
//middleware
app.use(express.json());

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
  : ["http://localhost:3000", "http://172.16.0.2:3000"];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  }),
);

// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@movie-matrix-cluster.kyhktuc.mongodb.net/?appName=movie-matrix-cluster`;
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@simple-crud-server.hfigrlp.mongodb.net/?appName=simple-crud-server`;
// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ekpzegp.mongodb.net/?appName=Cluster0";

// const uri = process.env.MONGODB_URI || "mongodb://localhost:27017";

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

    // Token Verification
    const verifyToken = (req, res, next) => {
      const token = req.cookies?.auth_token || req.headers.authorization?.split(" ")[1];
      
      if (!token) {
        return res.status(401).send({ message: "Unauthorized: No token provided" });
      }
      
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.decoded_email = decoded.email;
        next();
      } catch (error) {
        return res.status(401).send({ message: "Unauthorized: Invalid token" });
      }
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
          premium: false,
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
          premium: false,
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

    // Update user to premium
    app.post("/api/users/update-premium", verifyToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const result = await userCollection.updateOne(
          { email },
          { $set: { premium: true } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Successfully upgraded to Premium! 🚀" });
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
          premium: user.premium || false,
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
          premium: user.premium || false,
        });
      } catch (error) {
        console.error("Error in /api/users/login:", error);
        return res.status(500).json({ message: "Internal server error" });
      }
    });
    app.get("/api/users/me", async (req, res) => {
      try {
        const token = req.cookies.auth_token;

        if (!token) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await userCollection.findOne({
          email: decoded.email,
        });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json(user);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // SOCIAL LOGIN (Google) - Handles both new users and existing ones
    app.post("/api/users/social-login", async (req, res) => {
      try {
        const { name, email, photoURL } = req.body;
        // Check if user already exists
        let user = await userCollection.findOne({ email });
        if (!user) {
          // Create a new user if they don't exist
          const userDoc = {
            name,
            email,
            photoURL: photoURL || "",
            role: "user", 
            createdAt: new Date(),
            provider: "google" 
          };
          const result = await userCollection.insertOne(userDoc);
          user = { ...userDoc, _id: result.insertedId };
        }
        // Generate JWT Token
        const tokenPayload = {
          name: user.name,
          role: user.role,
          email: user.email,
        };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });
        // Set Cookie
        res.cookie("auth_token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.json({
          message: "Social login successful",
          token,
          user: { name: user.name, role: user.role, email: user.email }
        });
      } catch (error) {
        console.error("Error in /api/users/social-login:", error);
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
    // Get single movie by ID
    app.get("/movies/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const movie = await movieCollection.findOne({ _id: new ObjectId(id) });
        if (!movie) return res.status(404).send({ message: "Movie not found" });
        res.send(movie);
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    // app.patch("/api/movies/:id/watchlist", async (req, res) => {
    //   try {
    //     const { id } = req.params;
    //     const { watchlistStatus } = req.body;

    //     if (typeof watchlistStatus !== "boolean") {
    //       return res
    //         .status(400)
    //         .json({ message: "watchlistStatus must be a boolean value" });
    //     }

    //     const { ObjectId } = require("mongodb");

    //     if (!ObjectId.isValid(id)) {
    //       return res.status(400).json({ message: "Invalid movie ID" });
    //     }

    //     const result = await movieCollection.findOneAndUpdate(
    //       { _id: new ObjectId(id) },
    //       { $set: { watchlistStatus } },
    //       { returnDocument: "after" },
    //     );

    //     if (!result) {
    //       return res.status(404).json({ message: "Movie not found" });
    //     }

    //     res.json({
    //       message: "Watchlist status updated successfully",
    //       movie: result,
    //     });
    //   } catch (error) {
    //     console.error("Error in /api/movies/:id/watchlist:", error);
    //     res.status(500).json({ message: "Internal server error" });
    //   }
    // });

    app.post("/api/watchlist", async (req, res) => {
      try {
        const { userId, movieId } = req.body;

        if (!userId || !movieId) {
          return res
            .status(400)
            .json({ message: "userId and movieId are required" });
        }

        // Convert movieId to ObjectId if it's a valid ObjectId format, otherwise keep as string
        let movieObjectId;
        try {
          if (ObjectId.isValid(movieId) && movieId.length === 24) {
            movieObjectId = new ObjectId(movieId);
          } else {
            movieObjectId = movieId; // Keep as string if not valid ObjectId
          }
        } catch (error) {
          movieObjectId = movieId;
        }

        // Check if the combination already exists
        const existingEntry = await watchlistCollection.findOne({
          userId: userId, // Store userId as string (for Firebase UIDs)
          movieId: movieObjectId,
        });

        if (existingEntry) {
          return res
            .status(409)
            .json({ message: "Movie already in watchlist" });
        }

        const watchlistDoc = {
          userId: userId, // Store as string to support Firebase UIDs
          movieId: movieObjectId,
          createdAt: new Date(),
        };

        const result = await watchlistCollection.insertOne(watchlistDoc);

        res.status(201).json({
          message: "Movie added to watchlist successfully",
          watchlistId: result.insertedId,
          watchlist: watchlistDoc,
        });
      } catch (error) {
        console.error("Error in /api/watchlist:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.delete("/api/watchlist", async (req, res) => {
      try {
        const { userId, movieId } = req.body;

        if (!userId || !movieId) {
          return res
            .status(400)
            .json({ message: "userId and movieId are required" });
        }

        // Convert movieId to ObjectId if it's a valid ObjectId format, otherwise keep as string
        let movieObjectId;
        try {
          if (ObjectId.isValid(movieId) && movieId.length === 24) {
            movieObjectId = new ObjectId(movieId);
          } else {
            movieObjectId = movieId;
          }
        } catch (error) {
          movieObjectId = movieId;
        }

        const result = await watchlistCollection.deleteOne({
          userId: userId,
          movieId: movieObjectId,
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Watchlist entry not found" });
        }

        res.json({
          message: "Movie removed from watchlist successfully",
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error("Error in DELETE /api/watchlist:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.get("/api/watchlist/:userId", async (req, res) => {
      try {
        const { userId } = req.params;
        console.log("Fetching watchlist for userId:", userId);

        if (!userId) {
          return res.status(400).json({ message: "userId is required" });
        }

        // Fetch watchlist entries for the user
        const watchlistEntries = await watchlistCollection
          .find({ userId })
          .toArray();
        console.log("Found watchlist entries:", watchlistEntries.length);

        if (watchlistEntries.length === 0) {
          return res.json({
            message: "Watchlist is empty",
            count: 0,
            watchlist: [],
          });
        }

        // Manually fetch movie details for each entry
        const watchlistWithMovies = await Promise.all(
          watchlistEntries.map(async (entry) => {
            let movie = null;
            console.log(
              "Processing entry:",
              entry._id,
              "movieId type:",
              typeof entry.movieId,
              "value:",
              entry.movieId,
            );

            try {
              // Check if movieId is already an ObjectId instance
              if (entry.movieId instanceof ObjectId) {
                console.log("movieId is ObjectId instance");
                movie = await movieCollection.findOne({ _id: entry.movieId });
              }
              // Check if it's a valid ObjectId string
              else if (
                typeof entry.movieId === "string" &&
                ObjectId.isValid(entry.movieId) &&
                entry.movieId.length === 24
              ) {
                console.log("movieId is valid ObjectId string");
                movie = await movieCollection.findOne({
                  _id: new ObjectId(entry.movieId),
                });
              }
              // Otherwise try as-is
              else {
                console.log("movieId trying as-is");
                movie = await movieCollection.findOne({ _id: entry.movieId });
              }
              console.log("Found movie:", movie ? movie.title : "null");
            } catch (error) {
              console.error(
                `Error fetching movie for entry ${entry._id}:`,
                error.message,
              );
            }

            return {
              _id: entry._id,
              userId: entry.userId,
              movieId: entry.movieId,
              createdAt: entry.createdAt,
              movie: movie,
            };
          }),
        );

        console.log("Processed all entries, sorting...");

        // Sort by creation date (newest first)
        watchlistWithMovies.sort(
          (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
        );

        res.json({
          message: "Watchlist fetched successfully",
          count: watchlistWithMovies.length,
          watchlist: watchlistWithMovies,
        });
      } catch (error) {
        console.error("Error in GET /api/watchlist/:userId:", error);
        res
          .status(500)
          .json({ message: "Internal server error", error: error.message });
      }
    });

    //payment related apis
    app.post("/create-checkout-session", async (req, res) => {
      try {
        const { productName, price, quantity } = req.body;

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: { name: productName },
                unit_amount: price * 100,
              },
              quantity,
            },
          ],
          mode: "payment",
          success_url: "http://localhost:3000/payment-success",
          cancel_url: "http://localhost:3000/payment-cancel",
        });

        // ✅ Send session URL
        res.json({ url: session.url });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Stripe session creation failed" });
      }
    });

    // update primium
    app.post("/api/users/update-premium", async (req, res) => {
      try {
        const token = req.cookies.auth_token;
        if (!token) {
          return res.status(401).json({ message: "Unauthorized: No token" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const email = decoded.email;

        // Update premium to true in MongoDB
        const result = await userCollection.updateOne(
          { email },
          { $set: { premium: true } },
        );

        if (result.modifiedCount > 0) {
          return res.json({ message: "Premium activated successfully!" });
        } else {
          return res.status(400).json({ message: "Premium upgrade failed" });
        }
      } catch (err) {
        console.error("Error in /update-premium:", err);
        return res.status(500).json({ message: "Server error" });
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