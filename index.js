
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

export function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    try {
      const user = await client.db().collection("user").findOne({
        id: req.user.sub,
      });

      if (!user) {
        return res.status(401).json({
          message: "User not found.",
        });
      }

      if (!allowedRoles.includes(user.role)) {
        return res.status(403).json({
          message: "Access denied: Insufficient permissions.",
        });
      }

      req.authUser = user;
      next();
    } catch (error) {
      console.error("Role verification failed:", error);

      return res.status(500).json({
        message: "Role verification failed.",
      });
    }
  };
}


app.post(
  "/api/services",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {  try {
    const {
      title,
      category,
      description,
      startingPrice,
      serviceMode,
      image,
    } = req.body;

    if (
      !title ||
      !category ||
      !description ||
      !startingPrice ||
      !serviceMode ||
      !image
    ) {
      return res.status(400).json({
        message: "All service fields are required.",
      });
    }

    const db = client.db();

    const user = req.authUser;

    const newService = {
      title,
      category,
      description,
      startingPrice: Number(startingPrice),
      serviceMode,
      image,
      technicianId: req.user.sub,
      technicianName: user.name,
      status: "pending",
      createdAt: new Date(),
    };

    const result = await db.collection("services").insertOne(newService);

    res.status(201).json({
      message: "Service submitted successfully!",
      serviceId: result.insertedId,
    });
  } catch (error) {
    console.error("Add service error:", error);

    res.status(500).json({
      message: "Failed to add service.",
    });
  }
});

app.get(
  "/api/my-services",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      const db = client.db();

      const filter = {
        technicianId: req.user.sub,
      };

      const { status } = req.query;

      if (status && status !== "all") {
        filter.status = status;
      }

      const services = await db
        .collection("services")
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).json({
        message: "Services fetched successfully!",
        services,
      });
    } catch (error) {
      console.error("Get my services error:", error);

      res.status(500).json({
        message: "Failed to fetch services.",
      });
    }
  }
);


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