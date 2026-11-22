
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import "dotenv/config";

const PORT = 5000;
const app = express();

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

const client = new MongoClient(process.env.MONGO_URI);

const JWKS = createRemoteJWKSet(
  new URL(
    process.env.BETTER_AUTH_JWKS_URL ||
      "http://localhost:3000/api/auth/jwks"
  )
);

// MongoDB connection
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    throw err;
  }
}

// JWT verification middleware
export async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Unauthorized: Token is missing",
      });
    }

    const token = authHeader.split(" ")[1];

    const { payload } = await jwtVerify(token, JWKS);

    req.user = payload;

    next();
  } catch (error) {
    console.error("JWT verification failed:", error);

    return res.status(401).json({
      message: "Unauthorized: Invalid token",
    });
  }
}
app.get("/api/protected", verifyToken, (req, res) => {
  res.status(200).json({
    message: "JWT verification successful!",
    user: req.user,
  });
});
async function startServer() {
  try {
    await connectToMongoDB();

    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
  }
}

startServer();