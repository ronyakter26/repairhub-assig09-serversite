
import express from "express";
import cors from "cors";
import Stripe from "stripe";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import "dotenv/config";

const PORT = process.env.PORT || 5000;
const app = express();

const client = new MongoClient(process.env.MONGO_URI);

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const JWKS = createRemoteJWKSet(
  new URL(
    process.env.BETTER_AUTH_JWKS_URL ||
      "http://localhost:3000/api/auth/jwks"
  )
);

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      process.env.FRONTEND_URL,
    ].filter(Boolean),
    credentials: true,
  })
);
// Connect to MongoDB before handling requests
app.use(async (req, res, next) => {
  try {
    await connectToMongoDB();
    next();
  } catch (error) {
    console.error("MongoDB connection failed:", error);
    res.status(500).json({
      message: "Database connection failed.",
    });
  }
});

// Stripe webhook must receive the raw body
app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(503).json({
        message: "Stripe webhook is not configured.",
      });
    }

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (error) {
      return res.status(400).send(`Webhook Error: ${error.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        if (session.payment_status === "paid") {
          await markBookingPaid(session);
        }
      }

      return res.json({ received: true });
    } catch (error) {
      console.error("Webhook processing error:", error);
      return res.status(500).json({
        message: "Webhook processing failed.",
      });
    }
  }
);

app.use(express.json());

app.use((req, res, next) => {
  console.log("Incoming Request:", req.method, req.url);
  next();
});

const db = () => client.db();

let mongoConnectionPromise;

export async function connectToMongoDB() {
  if (!mongoConnectionPromise) {
    mongoConnectionPromise = client.connect();
  }

  await mongoConnectionPromise;
  return client;
}

// Authentication
export async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Unauthorized: Token is missing.",
      });
    }

    const token = authHeader.split(" ")[1];
    const { payload } = await jwtVerify(token, JWKS);

    req.user = payload;
    next();
  } catch (error) {
    console.error("JWT verification failed:", error);

    return res.status(401).json({
      message: "Unauthorized: Invalid token.",
    });
  }
}

export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const user = req.user;

    if (!user?.role) {
      return res.status(401).json({
        message: "User role is missing from token.",
      });
    }

    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({
        message: "Access denied.",
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

function validId(id) {
  return ObjectId.isValid(id);
}

function serviceOwnerFilter(req) {
  return {
    $or: [
      { technicianEmail: req.authUser.email },
      { technicianId: req.user.sub },
    ],
  };
}

function bookingOwnerFilter(req) {
  return {
    $or: [
      { customerEmail: req.authUser.email },
      { customerId: req.user.sub },
    ],
  };
}

function frontendUrl() {
  return (
    process.env.FRONTEND_URL ||
    "http://localhost:3000"
  ).replace(/\/$/, "");
}

async function markBookingPaid(session) {
  const bookingId = session.metadata?.bookingId;

  if (!bookingId || !validId(bookingId)) {
    throw new Error("Invalid booking ID in Stripe session.");
  }

  const database = db();
  const bookings = database.collection("bookings");
  const payments = database.collection("payments");

  const booking = await bookings.findOne({
    _id: new ObjectId(bookingId),
  });

  if (!booking) {
    throw new Error("Booking not found.");
  }

  if (
    booking.paymentStatus === "paid" &&
    booking.stripeSessionId === session.id
  ) {
    return;
  }

  if (booking.status !== "completed") {
    throw new Error("Booking is not completed.");
  }

  if (session.payment_status !== "paid") {
    throw new Error("Payment is not completed.");
  }

  if (
    Math.round(Number(booking.finalAmount) * 100) !==
    session.amount_total
  ) {
    throw new Error("Payment amount does not match.");
  }

  await payments.updateOne(
    { stripeSessionId: session.id },
    {
      $setOnInsert: {
        bookingId,
        serviceTitle: booking.serviceTitle,
        customerName: booking.customerName,
        customerEmail: booking.customerEmail,
        technicianName: booking.technicianName,
        technicianEmail: booking.technicianEmail,
        amount: Number(booking.finalAmount),
        currency: "usd",
        transactionId: session.payment_intent,
        stripeSessionId: session.id,
        paymentStatus: "paid",
        paidAt: new Date(),
      },
    },
    { upsert: true }
  );

  await bookings.updateOne(
    {
      _id: new ObjectId(bookingId),
      paymentStatus: { $ne: "paid" },
    },
    {
      $set: {
        paymentStatus: "paid",
        stripeSessionId: session.id,
        paidAt: new Date(),
      },
    }
  );
}

// Health
app.get("/", (req, res) => {
  res.json({ message: "FixMate Backend is running!" });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({ message: "API is working!" });
});

// Add service - Technician
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
      console.log("ADD SERVICE BODY:", req.body);

      if (
        !title?.trim() ||
        !category ||
        !description?.trim() ||
        !Number.isFinite(Number(basePrice)) ||
        Number(basePrice) <= 0 ||
        !estimatedDuration?.trim() ||
        !["Home Visit", "Shop Drop-off"].includes(serviceMode) ||
        !serviceArea?.trim() ||
        !image?.trim()
      ) {
        return res.status(400).json({
          message: "Please provide all valid service fields.",
        });
      }

      if (!req.authUser.email || !req.authUser.name) {
        return res.status(400).json({
          message: "Technician information is missing.",
        });
      }

      const newService = {
        title: title.trim(),
        category,
        description: description.trim(),
        image: image.trim(),
        basePrice: Number(basePrice),
        estimatedDuration: estimatedDuration.trim(),
        serviceMode,
        serviceArea: serviceArea.trim(),
        technicianName: req.authUser.name,
        technicianEmail: req.authUser.email,
        technicianId: req.user.sub,
        approvalStatus: "pending",
        isAvailable: true,
        createdAt: new Date(),
      };

      const result = await db()
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

// Technician services
app.get(
  "/api/my-services",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      const { status } = req.query;

      const filter = {
        $or: [
          { technicianEmail: req.authUser.email },
          { technicianId: req.user.sub },
        ],
      };

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

      const services = await db()
        .collection("services")
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      return res.json({
        services: services.map((service) => ({
          ...service,
          startingPrice:
            service.basePrice ?? service.startingPrice,
          status:
            service.approvalStatus ?? service.status,
        })),
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch services.",
      });
    }
  }
);

// Update technician service
app.patch(
  "/api/services/:id",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid service ID.",
        });
      }

      const allowed = [
        "title",
        "category",
        "description",
        "basePrice",
        "estimatedDuration",
        "serviceMode",
        "serviceArea",
        "image",
        "isAvailable",
      ];

      const updates = {};

      for (const key of allowed) {
        if (req.body[key] !== undefined) {
          updates[key] = req.body[key];
        }
      }

      if (updates.basePrice !== undefined) {
        updates.basePrice = Number(updates.basePrice);

        if (
          !Number.isFinite(updates.basePrice) ||
          updates.basePrice <= 0
        ) {
          return res.status(400).json({
            message: "Invalid base price.",
          });
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          message: "No valid fields to update.",
        });
      }

      const result = await db()
        .collection("services")
        .updateOne(
          {
            _id: new ObjectId(req.params.id),
            ...serviceOwnerFilter(req),
          },
          { $set: updates }
        );

      if (!result.matchedCount) {
        return res.status(404).json({
          message: "Service not found or access denied.",
        });
      }

      return res.json({
        message: "Service updated successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to update service.",
      });
    }
  }
);

// Delete technician service
app.delete(
  "/api/services/:id",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid service ID.",
        });
      }

      const result = await db()
        .collection("services")
        .deleteOne({
          _id: new ObjectId(req.params.id),
          ...serviceOwnerFilter(req),
        });

      if (!result.deletedCount) {
        return res.status(404).json({
          message: "Service not found or access denied.",
        });
      }

      return res.json({
        message: "Service deleted successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to delete service.",
      });
    }
  }
);

// Public services with search, category and sort
app.get("/api/services", async (req, res) => {
  try {
    const search =
      typeof req.query.search === "string"
        ? req.query.search.trim()
        : "";

    const category =
      typeof req.query.category === "string"
        ? req.query.category.trim()
        : "all";

    const sort = req.query.sort || "newest";

    const filter = {
      $and: [
        {
          $or: [
            { approvalStatus: "approved" },
            { status: "approved" },
          ],
        },
        {
          $or: [
            { isAvailable: true },
            { isAvailable: { $exists: false } },
          ],
        },
      ],
    };

    if (search) {
      const safeSearch = search.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      filter.$and.push({
        $or: [
          { title: { $regex: safeSearch, $options: "i" } },
          { description: { $regex: safeSearch, $options: "i" } },
          { category: { $regex: safeSearch, $options: "i" } },
        ],
      });
    }

    if (category !== "all") {
      filter.$and.push({ category });
    }

    let sortOption = { createdAt: -1 };

    if (sort === "price-low") {
      sortOption = { basePrice: 1 };
    } else if (sort === "price-high") {
      sortOption = { basePrice: -1 };
    }

    const services = await db()
      .collection("services")
      .find(filter)
      .sort(sortOption)
      .toArray();

    return res.json({
      total: services.length,
      services,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Failed to fetch services.",
    });
  }
});

// Single service
app.get("/api/services/:id", async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid service ID.",
      });
    }

    const service = await db()
      .collection("services")
      .findOne({
        _id: new ObjectId(req.params.id),
        $or: [
          { approvalStatus: "approved" },
          { status: "approved" },
        ],
        $and: [
          {
            $or: [
              { isAvailable: true },
              { isAvailable: { $exists: false } },
            ],
          },
        ],
      });

    if (!service) {
      return res.status(404).json({
        message: "Service not found.",
      });
    }

    return res.json({ service });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Failed to fetch service.",
    });
  }
});

// Create booking - Customer
app.post(
  "/api/bookings",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      const {
        serviceId,
        customerPhone,
        address,
        preferredDate,
        problemDescription,
      } = req.body;

      if (
        !validId(serviceId) ||
        !customerPhone?.trim() ||
        !address?.trim() ||
        !preferredDate ||
        !problemDescription?.trim() ||
        problemDescription.trim().length < 20
      ) {
        return res.status(400).json({
          message: "Please provide all valid booking fields.",
        });
      }

      if (!req.authUser.email || !req.authUser.name) {
        return res.status(400).json({
          message: "Customer information is missing.",
        });
      }

      const selectedDate = new Date(preferredDate);

      if (
        Number.isNaN(selectedDate.getTime()) ||
        selectedDate.setHours(0, 0, 0, 0) <
          new Date().setHours(0, 0, 0, 0)
      ) {
        return res.status(400).json({
          message: "Preferred date must be today or a future date.",
        });
      }

      const database = db();

      const service = await database
        .collection("services")
        .findOne({
          _id: new ObjectId(serviceId),
          approvalStatus: "approved",
          isAvailable: true,
        });

      if (!service) {
        return res.status(404).json({
          message: "Service is not available.",
        });
      }

      if (
        service.technicianEmail === req.authUser.email ||
        service.technicianId === req.user.sub
      ) {
        return res.status(403).json({
          message: "You cannot book your own service.",
        });
      }

      const duplicate = await database
        .collection("bookings")
        .findOne({
          serviceId,
          customerEmail: req.authUser.email,
          status: {
            $in: ["requested", "accepted", "in-progress"],
          },
        });

      if (duplicate) {
        return res.status(409).json({
          message: "You already have an active request for this service.",
        });
      }

      const booking = {
        serviceId,
        serviceTitle: service.title,
        serviceImage: service.image,
        category: service.category,
        basePrice: Number(service.basePrice),
        technicianName: service.technicianName,
        technicianEmail: service.technicianEmail,
        customerName: req.authUser.name,
        customerEmail: req.authUser.email,
        customerId: req.user.sub,
        customerPhone: customerPhone.trim(),
        address: address.trim(),
        preferredDate: selectedDate,
        problemDescription: problemDescription.trim(),
        status: "requested",
        finalAmount: Number(service.basePrice),
        paymentStatus: "unpaid",
        createdAt: new Date(),
      };

      const result = await database
        .collection("bookings")
        .insertOne(booking);

      return res.status(201).json({
        message: "Repair request submitted successfully.",
        bookingId: result.insertedId,
      });
    } catch (error) {
      console.error("Create booking error:", error);
      return res.status(500).json({
        message: "Failed to create booking.",
      });
    }
  }
);

// Customer bookings
app.get(
  "/api/bookings/my",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      const bookings = await db()
        .collection("bookings")
        .find(bookingOwnerFilter(req))
        .sort({ createdAt: -1 })
        .toArray();

      return res.json({ bookings });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch bookings.",
      });
    }
  }
);

// Cancel customer booking
app.patch(
  "/api/bookings/:id/cancel",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid booking ID.",
        });
      }

      const result = await db()
        .collection("bookings")
        .updateOne(
          {
            _id: new ObjectId(req.params.id),
            ...bookingOwnerFilter(req),
            status: "requested",
          },
          {
            $set: { status: "cancelled" },
          }
        );

      if (!result.modifiedCount) {
        return res.status(400).json({
          message: "Booking cannot be cancelled.",
        });
      }

      return res.json({
        message: "Booking cancelled successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to cancel booking.",
      });
    }
  }
);

// Technician bookings
app.get(
  "/api/bookings/technician",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      const bookings = await db()
        .collection("bookings")
        .find({
          technicianEmail: req.authUser.email,
        })
        .sort({ createdAt: -1 })
        .toArray();

      return res.json({ bookings });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch technician bookings.",
      });
    }
  }
);

// Technician booking status update
app.patch(
  "/api/bookings/:id/status",
  verifyToken,
  requireRole("technician"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid booking ID.",
        });
      }

      const { status, finalAmount } = req.body;

      const booking = await db()
        .collection("bookings")
        .findOne({
          _id: new ObjectId(req.params.id),
          technicianEmail: req.authUser.email,
        });

      if (!booking) {
        return res.status(404).json({
          message: "Booking not found.",
        });
      }

      const transitions = {
        requested: ["accepted", "rejected"],
        accepted: ["in-progress"],
        "in-progress": ["completed"],
      };

      if (!transitions[booking.status]?.includes(status)) {
        return res.status(400).json({
          message: "Invalid booking status transition.",
        });
      }

      const updates = { status };

      if (status === "completed") {
        const amount = Number(finalAmount);

        if (!Number.isFinite(amount) || amount <= 0) {
          return res.status(400).json({
            message: "A valid final amount is required.",
          });
        }

        updates.finalAmount = amount;
      }

      await db()
        .collection("bookings")
        .updateOne(
          { _id: booking._id },
          { $set: updates }
        );

      return res.json({
        message: "Booking status updated successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to update booking status.",
      });
    }
  }
);

// Stripe Checkout - Customer
app.post(
  "/api/payments/create-checkout-session",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      if (!stripe) {
        return res.status(503).json({
          message: "Stripe is not configured. Add STRIPE_SECRET_KEY to server .env.",
        });
      }

      const { bookingId } = req.body;

      if (!validId(bookingId)) {
        return res.status(400).json({
          message: "Invalid booking ID.",
        });
      }

      const booking = await db()
        .collection("bookings")
        .findOne({
          _id: new ObjectId(bookingId),
          ...bookingOwnerFilter(req),
        });

      if (!booking) {
        return res.status(404).json({
          message: "Booking not found.",
        });
      }

      if (
        booking.status !== "completed" ||
        booking.paymentStatus !== "unpaid"
      ) {
        return res.status(400).json({
          message: "Only completed and unpaid bookings can be paid.",
        });
      }

      const amount = Math.round(
        Number(booking.finalAmount) * 100
      );

      if (!Number.isSafeInteger(amount) || amount <= 0) {
        return res.status(400).json({
          message: "Invalid payment amount.",
        });
      }

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        customer_email: req.authUser.email,
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: booking.serviceTitle,
                description: "FixMate repair service",
              },
              unit_amount: amount,
            },
            quantity: 1,
          },
        ],
        metadata: {
          bookingId: booking._id.toString(),
        },
        success_url:
          `${frontendUrl()}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url:
          `${frontendUrl()}/payment/cancel`,
      });

      await db()
        .collection("bookings")
        .updateOne(
          { _id: booking._id },
          { $set: { stripeSessionId: session.id } }
        );

      return res.json({
        url: session.url,
        sessionId: session.id,
      });
    } catch (error) {
      console.error("Stripe checkout error:", error);
      return res.status(500).json({
        message: "Failed to create checkout session.",
      });
    }
  }
);

// Verify Stripe payment after checkout
app.post(
  "/api/payments/verify",
  verifyToken,
  requireRole("customer"),
  async (req, res) => {
    try {
      if (!stripe) {
        return res.status(503).json({
          message: "Stripe is not configured.",
        });
      }

      const { sessionId } = req.body;

      if (!sessionId) {
        return res.status(400).json({
          message: "Stripe session ID is required.",
        });
      }

      const session = await stripe.checkout.sessions.retrieve(
        sessionId
      );

      const bookingId = session.metadata?.bookingId;

      if (!bookingId || !validId(bookingId)) {
        return res.status(400).json({
          message: "Invalid booking information.",
        });
      }

      const booking = await db()
        .collection("bookings")
        .findOne({
          _id: new ObjectId(bookingId),
          ...bookingOwnerFilter(req),
        });

      if (!booking) {
        return res.status(404).json({
          message: "Booking not found.",
        });
      }

      if (booking.stripeSessionId !== session.id) {
        return res.status(403).json({
          message: "Payment session does not match this booking.",
        });
      }

      if (session.payment_status !== "paid") {
        return res.status(400).json({
          message: "Payment has not been completed.",
        });
      }

      await markBookingPaid(session);

      return res.json({
        message: "Payment verified successfully.",
        paymentStatus: "paid",
      });
    } catch (error) {
      console.error("Payment verification error:", error);
      return res.status(500).json({
        message: "Payment verification failed.",
      });
    }
  }
);

// Admin: users
app.get(
  "/api/admin/users",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const users = await db()
        .collection("users")
        .find({})
        .project({
          name: 1,
          email: 1,
          role: 1,
          image: 1,
        })
        .toArray();

      return res.json({ users });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch users.",
      });
    }
  }
);

// Admin: change user role
app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { role } = req.body;

      if (!["customer", "technician", "admin"].includes(role)) {
        return res.status(400).json({
          message: "Invalid role.",
        });
      }

      const userId = req.params.id;

      const filter = validId(userId)
        ? {
            $or: [
              { _id: new ObjectId(userId) },
              { _id: userId },
            ],
          }
        : { _id: userId };

      const result = await db()
        .collection("users")
        .updateOne(filter, {
          $set: { role },
        });

      if (!result.matchedCount) {
        return res.status(404).json({
          message: "User not found.",
        });
      }

      return res.json({
        message: "User role updated successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to update user role.",
      });
    }
  }
);

// Admin: get all services
app.get(
  "/api/admin/services",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const services = await db()
        .collection("services")
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.json({ services });
    } catch (error) {
      console.error("Admin services fetch error:", error);

      return res.status(500).json({
        message: "Failed to fetch services.",
      });
    }
  }
);


// Admin: approve or reject service
app.patch(
  "/api/admin/services/:id/approval",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid service ID.",
        });
      }

      const { approvalStatus } = req.body;

      if (!["approved", "rejected"].includes(approvalStatus)) {
        return res.status(400).json({
          message: "Invalid approval status.",
        });
      }

      const result = await db()
        .collection("services")
        .updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              approvalStatus,
              updatedAt: new Date(),
            },
          }
        );

      if (!result.matchedCount) {
        return res.status(404).json({
          message: "Service not found.",
        });
      }

      return res.json({
        message: "Service approval updated.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to update service approval.",
      });
    }
  }
);

// Admin: all bookings
app.get(
  "/api/admin/bookings",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const bookings = await db()
        .collection("bookings")
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      return res.json({ bookings });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch bookings.",
      });
    }
  }
);

// Admin: all payments
app.get(
  "/api/admin/payments",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    try {
      const payments = await db()
        .collection("payments")
        .find({})
        .sort({ paidAt: -1 })
        .toArray();

      return res.json({ payments });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to fetch payments.",
      });
    }
  }
);

// Update user profile
app.patch(
  "/api/users/profile",
  verifyToken,
  async (req, res) => {
    try {
      const { name, phone, address, image } = req.body;
      const updates = {};

      if (typeof name === "string" && name.trim()) {
        updates.name = name.trim();
      }

      if (typeof phone === "string") {
        updates.phone = phone.trim();
      }

      if (typeof address === "string") {
        updates.address = address.trim();
      }

      if (typeof image === "string") {
        updates.image = image.trim();
      }

      if (!Object.keys(updates).length) {
        return res.status(400).json({
          message: "No valid profile fields provided.",
        });
      }

      const result = await db()
        .collection("users")
        .updateOne(
          { email: req.user.email },
          { $set: updates }
        );

      if (!result.matchedCount) {
        return res.status(404).json({
          message: "User profile not found.",
        });
      }

      return res.json({
        message: "Profile updated successfully.",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Failed to update profile.",
      });
    }
  }
);

// Protected route
app.get(
  "/api/protected",
  verifyToken,
  (req, res) => {
    return res.json({
      message: "JWT verification successful!",
      user: req.user,
    });
  }
);

// Vercel serverless export
export default app;

// Local development server
if (process.env.NODE_ENV !== "production") {
  connectToMongoDB()
    .then(() => {
      app.listen(PORT, () => {
        console.log("FIXMATE BACKEND FILE IS RUNNING");
        console.log(`Server is running on port ${PORT}`);
      });
    })
    .catch((error) => {
      console.error("Server startup failed:", error);
    });
}
