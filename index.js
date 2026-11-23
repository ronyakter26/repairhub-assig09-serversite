
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import "dotenv/config";

const PORT = process.env.PORT || 5000;
const app = express();

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      process.env.FRONTEND_URL,
    ].filter(Boolean),
    credentials: true,
  })
);

app.use(express.json());

app.use((req, res, next) => {
  console.log("Incoming Request:", req.method, req.url);
  next();
});

const client = new MongoClient(process.env.MONGO_URI);

const JWKS = createRemoteJWKSet(
  new URL(
    process.env.BETTER_AUTH_JWKS_URL ||
      "http://localhost:3000/api/auth/jwks"
  )
);

export async function connectToMongoDB() {
  await client.connect();
  console.log("You successfully connected to MongoDB!");
  return client;
}

export async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
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
  return (req, res, next) => {
    const user = req.user;

    if (!user || !user.role) {
      return res.status(401).json({
        message: "User information missing from token.",
      });
    }

    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({
        message: "Access denied: Insufficient permissions.",
      });
    }

    req.authUser = {
      id: user.sub,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    next();
  };
}

// Add Service
app.post(
  "/api/services",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      const {
        title,
        category,
        description,
        basePrice,
        estimatedDuration,
        serviceMode,
        serviceArea,
        image,
      } = req.body;

      if (
        !title?.trim() ||
        !category ||
        !description?.trim() ||
        !Number.isFinite(Number(basePrice)) ||
        Number(basePrice) <= 0 ||
        !estimatedDuration?.trim() ||
        !["Home Visit", "Shop Drop-off"].includes(serviceMode) ||
        !serviceArea?.trim() ||
        !image
      ) {
        return res.status(400).json({
          message: "Please provide all valid service fields.",
        });
      }

      const technicianEmail = req.authUser.email;
      const technicianName = req.authUser.name;

      if (!technicianEmail || !technicianName) {
        return res.status(400).json({
          message:
            "Technician name or email is missing from your authentication token.",
        });
      }

      const db = client.db();

      const newService = {
        title: title.trim(),
        category,
        description: description.trim(),
        image,
        basePrice: Number(basePrice),
        estimatedDuration: estimatedDuration.trim(),
        serviceMode,
        serviceArea: serviceArea.trim(),
        technicianName,
        technicianEmail,
        technicianId: req.user.sub,
        approvalStatus: "pending",
        isAvailable: true,
        createdAt: new Date(),
      };

      const result = await db
        .collection("services")
        .insertOne(newService);

      return res.status(201).json({
        message: "Service submitted successfully!",
        serviceId: result.insertedId,
      });
    } catch (error) {
      console.error("Add service error:", error);

      return res.status(500).json({
        message: "Failed to add service.",
      });
    }
  }
);

// Get technician's services
app.get(
  "/api/my-services",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      const db = client.db();

      const filter = {
        $or: [
          { technicianEmail: req.authUser.email },
          { technicianId: req.user.sub },
        ],
      };

      const { status } = req.query;

      if (status && status !== "all") {
        filter.$and = [
          {
            $or: [
              { approvalStatus: status },
              { status },
            ],
          },
        ];
      }

      const services = await db
        .collection("services")
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      const compatibleServices = services.map((service) => ({
        ...service,
        startingPrice: service.basePrice ?? service.startingPrice,
        status: service.approvalStatus ?? service.status,
      }));

      return res.status(200).json({
        message: "Services fetched successfully!",
        services: compatibleServices,
      });
    } catch (error) {
      console.error("Get my services error:", error);

      return res.status(500).json({
        message: "Failed to fetch services.",
      });
    }
  }
);

// Get public services with server-side search, category filter and sorting
app.get("/api/services", async (req, res) => {
  try {
    const db = client.db();

    const { search = "", category = "all", sort = "newest" } = req.query;

    const filter = {
      approvalStatus: "approved",
      isAvailable: true,
    };

    if (typeof search === "string" && search.trim()) {
      const safeSearch = search.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      filter.$or = [
        { title: { $regex: safeSearch, $options: "i" } },
        { description: { $regex: safeSearch, $options: "i" } },
        { category: { $regex: safeSearch, $options: "i" } },
      ];
    }

    if (
      typeof category === "string" &&
      category !== "all" &&
      category.trim()
    ) {
      filter.category = category.trim();
    }

    let sortOption = { createdAt: -1 };

    if (sort === "price-low") {
      sortOption = { basePrice: 1 };
    } else if (sort === "price-high") {
      sortOption = { basePrice: -1 };
    }

    const services = await db
      .collection("services")
      .find(filter)
      .sort(sortOption)
      .toArray();

    return res.status(200).json({
      message: "Services fetched successfully!",
      services,
    });
  } catch (error) {
    console.error("Get public services error:", error);

    return res.status(500).json({
      message: "Failed to fetch services.",
    });
  }
});

// Get one approved service by ID
app.get("/api/services/:id", async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        message: "Invalid service ID.",
      });
    }

    const db = client.db();

    const service = await db.collection("services").findOne({
      _id: new ObjectId(req.params.id),
      approvalStatus: "approved",
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        message: "Service not found.",
      });
    }

    return res.status(200).json({ service });
  } catch (error) {
    console.error("Get service details error:", error);

    return res.status(500).json({
      message: "Failed to fetch service details.",
    });
  }
});

// Protected route
app.get("/api/protected", verifyToken, (req, res) => {
  return res.status(200).json({
    message: "JWT verification successful!",
    user: req.user,
  });
});

// Start server
async function startServer() {
  try {
    await connectToMongoDB();

    app.listen(PORT, () => {
      console.log("FIXMATE BACKEND FILE IS RUNNING");
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
  }
}

startServer();
