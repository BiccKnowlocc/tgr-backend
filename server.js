/**
 * server.js — Tobermory Grocery Run backend
 *
 * Includes:
 * ✅ Google OAuth login (cross-site cookie)
 * ✅ Member portal (/member)
 * ✅ Orders API (/api/orders) + order history
 * ✅ Admin: orders list, order detail, picklist, packing list
 * ✅ Admin: archive + delete orders (so old orders don’t clutter)
 * ✅ Admin: export current (unarchived) orders to CSV (Excel-friendly)
 * ✅ Account-based saved profiles (GET/PUT /api/profile) used by your new index page
 * ✅ Frontend fallback remains: if /api/profile not reachable, the index page uses localStorage automatically
 *
 * Requires:
 * - models/User.js (must include `profile` field OR allow mixed)
 * - models/Counter.js (simple counter for TGR-00001 IDs)
 */

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const mongoose = require("mongoose");

const User = require("./models/User");
const Counter = require("./models/Counter");

// ===== Square SDK (kept, not used in this snippet but safe to keep) =====
const { SquareClient, SquareEnvironment } = require("square");

const SQUARE_ENV = (process.env.SQUARE_ENV || "sandbox").toLowerCase();
const square = new SquareClient({
  token: process.env.SQUARE_ACCESS_TOKEN,
  environment:
    SQUARE_ENV === "production"
      ? SquareEnvironment.Production
      : SquareEnvironment.Sandbox,
});
const SQUARE_LOCATION_ID = process.env.SQUARE_LOCATION_ID;

const app = express();

// =========================
// CONFIG
// =========================
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:8888",
  "http://localhost:3000",
];

// Render / reverse proxies
app.set("trust proxy", 1);

// =========================
// MIDDLEWARE
// =========================
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true); // curl/postman
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked origin: " + origin));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

// =========================
// DB
// =========================
if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI in environment variables.");
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// =========================
// SESSIONS
// =========================
app.use(
  session({
    name: "tgr.sid",
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // Render is https
      sameSite: "none", // cross-site cookies
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    },
  })
);

// =========================
// PASSPORT
// =========================
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || null);
  } catch (e) {
    done(e);
  }
});

function safeReturnToPath(p) {
  // Allow only local paths like "/admin" or "/member"
  if (!p || typeof p !== "string") return "/member";
  if (!p.startsWith("/")) return "/member";
  const allowed = ["/member", "/admin", "/admin/order", "/admin/picklist", "/admin/packing"];
  const base = p.split("?")[0];
  if (!allowed.includes(base)) return "/member";
  return p;
}

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: `${BASE_URL}/auth/google/callback`,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || "").toLowerCase();
        const photo = profile.photos?.[0]?.value || "";

        if (!email) return done(new Error("Google did not return an email address."));

        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            googleId: profile.id,
            email,
            name: profile.displayName || email,
            photo,
            membershipLevel: "none",
            membershipStatus: "inactive",
            renewalDate: null,
            discounts: [],
            perks: [],
            orderHistory: [],
            // profile field is optional; created lazily
          });
        } else {
          user.googleId = profile.id;
          user.name = profile.displayName || user.name;
          user.photo = photo || user.photo;
          await user.save();
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// =========================
// AUTH HELPERS
// =========================
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, error: "Not logged in" });
}

// Admin list comes from Render env var: ADMIN_EMAILS="you@gmail.com,other@gmail.com"
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

function isAdminUser(req) {
  const email = (req.user?.email || "").toLowerCase();
  return ADMIN_EMAILS.includes(email);
}

// For API endpoints: return JSON
function requireAdminApi(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "Not logged in" });
  if (!isAdminUser(req)) return res.status(403).json({ ok: false, error: "Forbidden" });
  return next();
}

// For HTML pages: redirect to Google login then return to page
function requireAdminPage(req, res, next) {
  if (!req.user) {
    const returnTo = encodeURIComponent(req.originalUrl || "/admin");
    return res.redirect(`/auth/google?returnTo=${returnTo}`);
  }
  if (!isAdminUser(req)) return res.status(403).send("Forbidden");
  return next();
}

// =========================
// RUN DATE CALC
// =========================
function computeNextRunDates() {
  const today = new Date();
  const day = today.getDay(); // 0=Sun
  const daysUntilSunday = ((7 - day) % 7) || 7; // next Sunday (not today)
  const runDate = new Date(today);
  runDate.setDate(today.getDate() + daysUntilSunday);

  const payDeadline = new Date(runDate);
  payDeadline.setDate(runDate.getDate() - 2); // Friday

  const listDeadline = new Date(runDate);
  listDeadline.setDate(runDate.getDate() - 1); // Saturday

  const followingRun = new Date(runDate);
  followingRun.setDate(runDate.getDate() + 14);

  return { runDate, payDeadline, listDeadline, followingRun };
}

// Fix common bad pasted path like /https://tgr-backend.onrender.com/...
app.get(/^\/https?:\/\/.*/i, (req, res) => res.redirect("/"));

// =========================
// ORDER CODE GENERATOR (TGR-00001)
// =========================
async function nextOrderCode() {
  // Counter model should use: { _id: String, seq: Number }
  const doc = await Counter.findOneAndUpdate(
    { _id: "order" },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  ).lean();

  const n = doc?.seq || 1;
  const padded = String(n).padStart(5, "0");
  return "TGR-" + padded;
}

// =========================
// ROUTES
// =========================
app.get("/health", (req, res) => res.send("OK server is running"));

// Homepage (backend)
app.get("/", (req, res) => {
  if (req.user) return res.redirect("/member");
  res.type("html").send(
    "<h1>TGR Backend</h1>" +
      '<p><a href="/auth/google">Login with Google</a></p>' +
      '<p><a href="/health">Health Check</a></p>' +
      "<p>BASE_URL: " +
      String(BASE_URL) +
      "</p>"
  );
});

// Start login (uses OAUTH state so it survives redirects even if session gets weird)
app.get(
  "/auth/google",
  (req, res, next) => {
    const returnTo = safeReturnToPath(req.query.returnTo || "/member");
    const state = Buffer.from(JSON.stringify({ returnTo }), "utf8").toString("base64url");
    req._oauthState = state;
    next();
  },
  (req, res, next) => {
    passport.authenticate("google", {
      scope: ["profile", "email"],
      prompt: "select_account",
      state: req._oauthState,
    })(req, res, next);
  }
);

// OAuth callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    let returnTo = "/member";
    try {
      if (req.query.state) {
        const decoded = JSON.parse(
          Buffer.from(String(req.query.state), "base64url").toString("utf8")
        );
        returnTo = safeReturnToPath(decoded.returnTo);
      }
    } catch {}
    return res.redirect(returnTo);
  }
);

// Logout
app.get("/logout", (req, res) => {
  const fallback = "https://tobermorygroceryrun.ca/";
  const returnToRaw = req.query.returnTo || fallback;

  let returnTo = fallback;
  try {
    const u = new URL(returnToRaw);
    const host = u.hostname.toLowerCase();
    const allowed = ["tobermorygroceryrun.ca", "www.tobermorygroceryrun.ca"];
    if (allowed.includes(host)) returnTo = u.toString();
  } catch {}

  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("tgr.sid");
      res.redirect(returnTo);
    });
  });
});

// Who am I
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ ok: true, loggedIn: false });
  return res.json({
    ok: true,
    loggedIn: true,
    user: {
      email: req.user.email,
      name: req.user.name,
      photo: req.user.photo || "",
      membershipLevel: req.user.membershipLevel || "none",
      membershipStatus: req.user.membershipStatus || "inactive",
      renewalDate: req.user.renewalDate,
    },
  });
});

// =========================
// ACCOUNT-BASED SAVED PROFILE (for index.html)
// =========================
// The index page tries GET/PUT /api/profile first (account based), then falls back to localStorage if missing/unreachable.
// We implement the endpoints here (so it becomes truly account-based).

app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).lean();
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    // profile can be anything JSON-like: { version, defaultId, addresses[] }
    // If you haven’t added profile to the schema yet, Mongoose may drop it unless strict is false.
    // Best practice: add `profile: mongoose.Schema.Types.Mixed` to User model.
    const profile = user.profile || { version: 1, defaultId: "", addresses: [] };
    return res.json({ ok: true, profile });
  } catch (e) {
    console.error("GET /api/profile error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const profile = body.profile || body;

    // Light validation
    if (!profile || typeof profile !== "object") {
      return res.status(400).json({ ok: false, error: "Invalid profile payload" });
    }

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    user.profile = profile;
    await user.save();

    return res.json({ ok: true });
  } catch (e) {
    console.error("PUT /api/profile error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// =========================
// ORDERS API
// =========================

// Save order (auth required)
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const p = req.body || {};

    // Accept both snake_case (old) and camelCase (new)
    const primaryStore = String(p.primary_store ?? p.primaryStore ?? "").trim();
    const secondaryStore = String(p.secondary_store ?? p.secondaryStore ?? "").trim();
    const groceryList = String(p.grocery_list ?? p.groceryList ?? "").trim();

    const community = String(p.community ?? "").trim();
    const streetAddress = String(p.street_address ?? p.streetAddress ?? "").trim();
    const phone = String(p.phone ?? "").trim();

    const notes = String(
      p.grocery_notes ?? p.notes ?? p.dropoff_notes ?? p.dropoffNotes ?? ""
    ).trim();

    // Add-ons: accept multiple keys
    const addOns = {
      fastFood:
        (p.addon_fast_food ?? p.addOnFastFood ?? p.fastFood) === "yes" ||
        (p.addon_fast_food ?? p.addOnFastFood ?? p.fastFood) === true,
      liquor:
        (p.addon_liquor ?? p.addOnLiquor ?? p.liquor) === "yes" ||
        (p.addon_liquor ?? p.addOnLiquor ?? p.liquor) === true,
      printing:
        (p.addon_printing ?? p.addOnPrinting ?? p.printing) === "yes" ||
        (p.addon_printing ?? p.addOnPrinting ?? p.printing) === true,
      ride:
        (p.addon_ride ?? p.addOnRide ?? p.ride) === "yes" ||
        (p.addon_ride ?? p.addOnRide ?? p.ride) === true,
    };

    if (!primaryStore) return res.status(400).json({ ok: false, error: "Missing primary store" });
    if (!groceryList) return res.status(400).json({ ok: false, error: "Missing grocery list" });

    const { runDate, payDeadline, listDeadline, followingRun } = computeNextRunDates();
    const orderCode = await nextOrderCode();

    // IMPORTANT:
    // We create an explicit orderId so admin URLs are stable even if subdoc _id is not used consistently.
    const orderId = new mongoose.Types.ObjectId();

    const order = {
      _id: orderId,
      orderId: String(orderId),
      orderCode,
      createdAt: new Date(),
      runDate,
      payDeadline,
      listDeadline,
      followingRun,
      primaryStore,
      secondaryStore,
      community,
      streetAddress,
      phone,
      groceryList,
      notes,
      status: "submitted",
      addOns,
      archived: false,
      archivedAt: null,
    };

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    user.orderHistory = user.orderHistory || [];
    user.orderHistory.unshift(order);
    await user.save();

    return res.json({ ok: true, order });
  } catch (e) {
    console.error("POST /api/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Read order history (unarchived by default)
app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const includeArchived =
      String(req.query.includeArchived || "").trim() === "1" ||
      String(req.query.includeArchived || "").trim().toLowerCase() === "true";

    const user = await User.findById(req.user._id).lean();
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    let orders = user.orderHistory || [];
    if (!includeArchived) orders = orders.filter((o) => !o.archived);

    return res.json({ ok: true, orders });
  } catch (e) {
    console.error("GET /api/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// =========================
// ADMIN APIs
// =========================

// All orders (across users) — unarchived by default
app.get("/api/admin/orders", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const includeArchived =
      String(req.query.includeArchived || "").trim() === "1" ||
      String(req.query.includeArchived || "").trim().toLowerCase() === "true";

    const users = await User.find({}, { email: 1, name: 1, orderHistory: 1 }).lean();

    const orders = [];
    for (const u of users) {
      for (const o of u.orderHistory || []) {
        if (!includeArchived && o.archived) continue;
        orders.push({
          userId: String(u._id),
          userEmail: u.email,
          userName: u.name,
          orderId: String(o.orderId || o._id),
          orderCode: o.orderCode || "",
          createdAt: o.createdAt,
          runDate: o.runDate,
          community: o.community,
          primaryStore: o.primaryStore,
          status: o.status,
          archived: !!o.archived,
        });
      }
    }

    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return res.json({ ok: true, orders });
  } catch (e) {
    console.error("GET /api/admin/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Single order detail
app.get("/api/admin/orders/:userId/:orderId", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const { userId, orderId } = req.params;

    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const order = (user.orderHistory || []).find((o) => {
      const oid = String(o.orderId || o._id);
      return oid === String(orderId);
    });

    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    return res.json({
      ok: true,
      user: { id: String(user._id), email: user.email, name: user.name },
      order,
    });
  } catch (e) {
    console.error("GET /api/admin/orders/:userId/:orderId error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Archive an order
app.post("/api/admin/orders/:userId/:orderId/archive", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const { userId, orderId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const idx = (user.orderHistory || []).findIndex((o) => String(o.orderId || o._id) === String(orderId));
    if (idx < 0) return res.status(404).json({ ok: false, error: "Order not found" });

    user.orderHistory[idx].archived = true;
    user.orderHistory[idx].archivedAt = new Date();
    await user.save();

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST archive order error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Unarchive (optional convenience)
app.post("/api/admin/orders/:userId/:orderId/unarchive", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const { userId, orderId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const idx = (user.orderHistory || []).findIndex((o) => String(o.orderId || o._id) === String(orderId));
    if (idx < 0) return res.status(404).json({ ok: false, error: "Order not found" });

    user.orderHistory[idx].archived = false;
    user.orderHistory[idx].archivedAt = null;
    await user.save();

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST unarchive order error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Delete an order (hard delete)
app.delete("/api/admin/orders/:userId/:orderId", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const { userId, orderId } = req.params;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const before = user.orderHistory?.length || 0;
    user.orderHistory = (user.orderHistory || []).filter(
      (o) => String(o.orderId || o._id) !== String(orderId)
    );
    const after = user.orderHistory.length;

    if (after === before) return res.status(404).json({ ok: false, error: "Order not found" });

    await user.save();
    return res.json({ ok: true });
  } catch (e) {
    console.error("DELETE order error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Export current (unarchived) orders to CSV (Excel-friendly)
// Download: /api/admin/orders/export.csv
app.get("/api/admin/orders/export.csv", requireAuth, requireAdminApi, async (req, res) => {
  try {
    const users = await User.find({}, { email: 1, name: 1, orderHistory: 1 }).lean();

    // Build rows
    const rows = [];
    for (const u of users) {
      for (const o of u.orderHistory || []) {
        if (o.archived) continue;

        const add = o.addOns || {};
        const addOnsText = [
          add.fastFood ? "Fast Food" : null,
          add.liquor ? "Liquor" : null,
          add.printing ? "Printing" : null,
          add.ride ? "Ride" : null,
        ]
          .filter(Boolean)
          .join(", ");

        rows.push({
          orderCode: o.orderCode || "",
          orderId: String(o.orderId || o._id || ""),
          createdAt: o.createdAt ? new Date(o.createdAt).toISOString() : "",
          runDate: o.runDate ? new Date(o.runDate).toISOString().slice(0, 10) : "",
          name: u.name || "",
          email: u.email || "",
          community: o.community || "",
          streetAddress: o.streetAddress || "",
          phone: o.phone || "",
          primaryStore: o.primaryStore || "",
          secondaryStore: o.secondaryStore || "",
          addOns: addOnsText || "",
          notes: (o.notes || "").replace(/\r?\n/g, " "),
          groceryList: (o.groceryList || "").replace(/\r?\n/g, " "),
          status: o.status || "",
        });
      }
    }

    rows.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));

    function csvEscape(v) {
      const s = String(v ?? "");
      if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    }

    const header = [
      "orderCode",
      "orderId",
      "createdAt",
      "runDate",
      "name",
      "email",
      "community",
      "streetAddress",
      "phone",
      "primaryStore",
      "secondaryStore",
      "addOns",
      "notes",
      "groceryList",
      "status",
    ];

    const lines = [];
    lines.push(header.join(","));
    for (const r of rows) {
      lines.push(header.map((k) => csvEscape(r[k])).join(","));
    }

    const csv = lines.join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="tgr-current-orders.csv"');
    return res.send(csv);
  } catch (e) {
    console.error("GET export.csv error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// =========================
// MEMBER PAGE (/member) — unchanged functional behavior
// =========================
app.get("/member", (req, res) => {
  if (!req.user) return res.redirect("/");

  const u = req.user;
  const renewal = u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A";

  const perks = u.perks && u.perks.length ? u.perks : [
    "Priority booking on run days",
    "Reduced extra-store fees (based on tier)",
    "Faster issue resolution support",
  ];

  const discounts = u.discounts && u.discounts.length ? u.discounts : [
    "Member discounts apply to service/delivery fees (where applicable)",
  ];

  const orderRows = (u.orderHistory || [])
    .filter((o) => !o.archived)
    .slice()
    .reverse()
    .map((o) => {
      const created = o.createdAt ? new Date(o.createdAt).toLocaleDateString("en-CA") : "";
      const run = o.runDate ? new Date(o.runDate).toLocaleDateString("en-CA") : "—";
      const store = o.primaryStore || "—";
      const status = o.status || "submitted";
      const code = o.orderCode || o.orderId || "";
      return (
        "<tr>" +
        "<td>" + created + "</td>" +
        "<td>" + run + "</td>" +
        "<td>" + store + "</td>" +
        "<td><span class='badge'>" + status + "</span></td>" +
        "<td><span class='badge'>" + String(code) + "</span></td>" +
        "</tr>"
      );
    })
    .join("");

  const manageUrl = process.env.SQUARE_MANAGE_MEMBERSHIP_URL || "https://tobermorygroceryrun.ca/indexapp.html";
  const cancelUrl =
    process.env.SQUARE_CANCEL_MEMBERSHIP_URL ||
    "mailto:members@tobermorygroceryrun.ca?subject=Membership%20Cancellation%20Request";

  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>TGR Member Portal</title>
<style>
  :root{
    --bg:#0f1526; --card:#121a2e; --text:#ffffff;
    --muted:rgba(255,255,255,.75); --line:rgba(255,255,255,.14);
    --brand:#1f2a44; --accent:#e3342f; --soft:rgba(227,52,47,.12);
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.55}
  header{background:var(--brand);border-bottom:1px solid var(--line);padding:14px 14px}
  .wrap{max-width:980px;margin:0 auto;padding:0 14px}
  .hdr{display:flex;align-items:center;gap:12px}
  .logo{width:86px;height:auto;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:6px}
  h1{margin:0;font-size:1.25rem}
  .sub{margin:2px 0 0;color:var(--muted);font-size:.95rem}
  main{max-width:980px;margin:0 auto;padding:14px 14px 40px}
  .grid{display:grid;grid-template-columns:1.3fr .7fr;gap:12px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;box-shadow:0 12px 40px rgba(0,0,0,.35)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid var(--line);font-size:.85rem;color:var(--muted)}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.07);border:1px solid var(--line);font-size:.82rem}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 14px;border-radius:999px;
    border:1px solid rgba(255,255,255,.18);text-decoration:none;color:var(--text);font-weight:800}
  .btn.primary{background:var(--accent);border-color:rgba(0,0,0,.15)}
  .btn.ghost{background:transparent}
  .muted{color:var(--muted)}
  .tabs{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0}
  .tab{border:1px solid var(--line);background:rgba(255,255,255,.06);color:var(--text);padding:8px 12px;border-radius:999px;
    cursor:pointer;font-weight:800}
  .tab[aria-selected="true"]{background:var(--soft);border-color:rgba(227,52,47,.5)}
  .panel{display:none;margin-top:12px}
  .panel.active{display:block}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;font-size:.95rem}
  th{color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.06em}
  .run-info > div{margin:6px 0}
  hr{border:none;border-top:1px solid var(--line);margin:14px 0}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div class="hdr">
      <img src="/tgr_logo_tight_512.png" class="logo" alt="TGR logo" />
      <div>
        <h1>Member Portal</h1>
        <div class="sub">Signed in as ${u.email}</div>
      </div>
    </div>
  </div>
</header>

<main>
  <div class="grid">
    <section class="card">
      <div class="row" style="justify-content:space-between">
        <div class="row" style="gap:8px">
          <div class="pill">Name: <strong>${u.name || ""}</strong></div>
          <div class="pill">Status: <strong>${u.membershipStatus || "inactive"}</strong></div>
          <div class="pill">Level: <strong>${u.membershipLevel || "none"}</strong></div>
          <div class="pill">Renewal: <strong>${renewal}</strong></div>
        </div>
        <div class="row">
          <a class="btn ghost" href="/logout">Log out</a>
        </div>
      </div>

      <div class="tabs" role="tablist">
        <button class="tab" id="tab-membership" aria-selected="true" type="button">Membership</button>
        <button class="tab" id="tab-perks" aria-selected="false" type="button">Perks & Discounts</button>
        <button class="tab" id="tab-orders" aria-selected="false" type="button">Order History</button>
      </div>

      <div id="panel-membership" class="panel active">
        <p class="muted">Manage billing or request cancellation.</p>
        <div class="row">
          <a class="btn primary" href="${manageUrl}" target="_blank" rel="noopener">Manage / Pay Membership</a>
          <a class="btn ghost" href="${cancelUrl}" target="_blank" rel="noopener">Cancel / Request Cancellation</a>
        </div>
      </div>

      <div id="panel-perks" class="panel">
        <h3>Your Perks</h3>
        <ul>${perks.map((p) => `<li>${p}</li>`).join("")}</ul>
        <h3>Your Discounts</h3>
        <ul>${discounts.map((d) => `<li>${d}</li>`).join("")}</ul>
      </div>

      <div id="panel-orders" class="panel">
        <h3>Order History</h3>
        <table>
          <thead><tr><th>Submitted</th><th>Run Date</th><th>Store</th><th>Status</th><th>Order ID</th></tr></thead>
          <tbody>
            ${orderRows || `<tr><td colspan="5" class="muted">No orders on file yet.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>

    <aside class="card">
      <h3>Quick Links</h3>
      <div class="row" style="flex-direction:column;align-items:stretch">
        <a class="btn primary" href="https://tobermorygroceryrun.ca/?tab=order" target="_blank" rel="noopener">Place an Order</a>
        <a class="btn ghost" href="https://tobermorygroceryrun.ca/" target="_blank" rel="noopener">Open Main App</a>
        <a class="btn ghost" href="https://tobermorygroceryrun.ca/terms.html" target="_blank" rel="noopener">Terms & Conditions</a>
      </div>
    </aside>
  </div>
</main>

<script>
  const tabs = [
    { tab: "tab-membership", panel: "panel-membership" },
    { tab: "tab-perks", panel: "panel-perks" },
    { tab: "tab-orders", panel: "panel-orders" },
  ];

  function selectTab(tabId){
    tabs.forEach(({tab, panel}) => {
      const t = document.getElementById(tab);
      const p = document.getElementById(panel);
      const active = (tab === tabId);
      t.setAttribute("aria-selected", active ? "true" : "false");
      p.classList.toggle("active", active);
    });
  }

  tabs.forEach(({tab}) => {
    document.getElementById(tab).addEventListener("click", () => selectTab(tab));
  });
</script>
</body>
</html>`);
});

// =========================
// ADMIN HTML PAGES (redesigned + archive/delete + export CSV link)
// =========================

function escHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// /admin — list
app.get("/admin", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Orders</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--red:#E3342F;--bg:#0B0D10;--text:#E6E6E6;--muted:rgba(230,230,230,.72);--card:rgba(230,230,230,.06);--border:rgba(230,230,230,.14);}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);padding:14px;}
    a{color:var(--text);text-decoration:none;font-weight:800}
    a:hover{text-decoration:underline}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
    .pill{display:inline-block;padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:var(--card);font-size:13px;color:var(--muted)}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--text);font-weight:900;cursor:pointer}
    .btn.primary{background:var(--red);border-color:rgba(0,0,0,.2);color:#fff}
    .grid{display:grid;grid-template-columns:1fr;gap:12px}
    .card{border:1px solid var(--border);border-radius:16px;background:var(--card);padding:12px}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid rgba(230,230,230,.10);padding:10px 8px;text-align:left;font-size:14px;vertical-align:top}
    th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
    .muted{color:var(--muted)}
    .actions{display:flex;gap:8px;flex-wrap:wrap}
    .code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;opacity:.9}
  </style>
</head>
<body>
  <div class="top">
    <h2 style="margin:0;">Admin Orders</h2>
    <a class="btn" href="/admin/picklist">Picklist</a>
    <a class="btn" href="/admin/packing">Packing</a>
    <a class="btn" href="/api/admin/orders/export.csv">Export CSV</a>
    <a class="btn" href="/member">Member</a>
    <a class="btn" href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
    <span class="pill">Signed in as: ${escHtml(req.user?.email || "")}</span>
  </div>

  <div class="card">
    <div class="muted" style="margin-bottom:8px;">
      Showing current (unarchived) orders. Use “Archive” to hide completed orders from lists.
    </div>
    <div id="out">Loading…</div>
  </div>

<script>
async function api(url, opts){
  const r = await fetch(url, Object.assign({ credentials:"include" }, opts || {}));
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { r:r, data:data, text:text };
}

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, function(c){
    return { "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;" }[c];
  });
}

async function archiveOrder(userId, orderId){
  if(!confirm("Archive this order?")) return;
  const res = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId) + "/archive", { method:"POST" });
  if(!res.r.ok){ alert((res.data && res.data.error) ? res.data.error : ("Error " + res.r.status)); return; }
  load();
}

async function deleteOrder(userId, orderId){
  if(!confirm("DELETE this order permanently? This cannot be undone.")) return;
  const res = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId), { method:"DELETE" });
  if(!res.r.ok){ alert((res.data && res.data.error) ? res.data.error : ("Error " + res.r.status)); return; }
  load();
}

async function load(){
  const out = document.getElementById("out");
  out.textContent = "Loading…";

  const res = await api("/api/admin/orders");
  if(!res.r.ok || (res.data && res.data.ok===false)){
    out.textContent = (res.data && res.data.error) ? res.data.error : ("Error " + res.r.status);
    return;
  }

  const orders = (res.data && res.data.orders) ? res.data.orders : [];
  if(!orders.length){
    out.innerHTML = "<div class='muted'>No current orders.</div>";
    return;
  }

  let rows = "";
  for(const o of orders){
    const userId = String(o.userId || "");
    const orderId = String(o.orderId || "");
    const viewUrl = "/admin/order?userId=" + encodeURIComponent(userId) + "&orderId=" + encodeURIComponent(orderId);
    const created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";
    const run = o.runDate ? new Date(o.runDate).toLocaleDateString() : "";
    const code = o.orderCode || o.orderId || "";

    rows +=
      "<tr>" +
        "<td><div class='code'>" + esc(code) + "</div><div class='muted'>" + esc(created) + "</div></td>" +
        "<td>" + esc(o.userName || "") + "<div class='muted'>" + esc(o.userEmail || "") + "</div></td>" +
        "<td>" + esc(o.community || "") + "</td>" +
        "<td>" + esc(run) + "</td>" +
        "<td>" + esc(o.primaryStore || "") + "</td>" +
        "<td>" + esc(o.status || "") + "</td>" +
        "<td>" +
          "<div class='actions'>" +
            "<a class='btn' href='" + viewUrl + "'>View</a>" +
            "<button class='btn' onclick='archiveOrder(" + JSON.stringify(userId) + "," + JSON.stringify(orderId) + ")'>Archive</button>" +
            "<button class='btn' onclick='deleteOrder(" + JSON.stringify(userId) + "," + JSON.stringify(orderId) + ")'>Delete</button>" +
          "</div>" +
        "</td>" +
      "</tr>";
  }

  out.innerHTML =
    "<table>" +
      "<thead><tr>" +
        "<th>Order</th><th>Customer</th><th>Community</th><th>Run</th><th>Store</th><th>Status</th><th>Actions</th>" +
      "</tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
    "</table>";
}

load();
</script>
</body>
</html>`);
});

// /admin/order — detail (comfortable mobile reading)
app.get("/admin/order", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Order</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--red:#E3342F;--bg:#0B0D10;--text:#E6E6E6;--muted:rgba(230,230,230,.72);--card:rgba(230,230,230,.06);--border:rgba(230,230,230,.14);}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);padding:14px;}
    a{color:var(--text);text-decoration:none;font-weight:800}
    a:hover{text-decoration:underline}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--text);font-weight:900;cursor:pointer}
    .btn.primary{background:var(--red);border-color:rgba(0,0,0,.2);color:#fff}
    .card{border:1px solid var(--border);border-radius:16px;background:var(--card);padding:12px}
    .muted{color:var(--muted)}
    details{border:1px solid rgba(230,230,230,.10);border-radius:14px;background:rgba(230,230,230,.05);padding:10px;margin:10px 0}
    summary{cursor:pointer;font-weight:900}
    pre{white-space:pre-wrap;background:rgba(0,0,0,.20);border:1px solid rgba(230,230,230,.10);padding:10px;border-radius:12px;overflow:auto}
    .code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;opacity:.95}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .pill{display:inline-block;padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:var(--card);font-size:13px;color:var(--muted)}
  </style>
</head>
<body>
  <div class="top">
    <a class="btn" href="/admin">← Back</a>
    <a class="btn" href="/admin/picklist">Picklist</a>
    <a class="btn" href="/admin/packing">Packing</a>
    <a class="btn" href="/api/admin/orders/export.csv">Export CSV</a>
    <a class="btn" href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
  </div>

  <div class="card">
    <div id="out">Loading…</div>
  </div>

<script>
async function api(url, opts){
  const r = await fetch(url, Object.assign({ credentials:"include" }, opts || {}));
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { r:r, data:data, text:text };
}

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, function(c){
    return { "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;" }[c];
  });
}

function addOnsText(o){
  const add = (o && (o.addOns || o.addons)) ? (o.addOns || o.addons) : {};
  const parts = [];
  if(add.fastFood) parts.push("Fast Food");
  if(add.liquor) parts.push("Liquor");
  if(add.printing) parts.push("Printing");
  if(add.ride) parts.push("Ride");
  return parts.length ? parts.join(", ") : "None";
}

async function archiveOrder(userId, orderId){
  if(!confirm("Archive this order?")) return;
  const res = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId) + "/archive", { method:"POST" });
  if(!res.r.ok){ alert((res.data && res.data.error) ? res.data.error : ("Error " + res.r.status)); return; }
  load();
}

async function deleteOrder(userId, orderId){
  if(!confirm("DELETE permanently? This cannot be undone.")) return;
  const res = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId), { method:"DELETE" });
  if(!res.r.ok){ alert((res.data && res.data.error) ? res.data.error : ("Error " + res.r.status)); return; }
  window.location.href = "/admin";
}

async function load(){
  const out = document.getElementById("out");

  const params = new URLSearchParams(location.search);
  const userId = params.get("userId");
  const orderId = params.get("orderId");

  if(!userId || !orderId){
    out.textContent = "Missing userId or orderId in URL.";
    return;
  }

  const res = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId));
  if(!res.r.ok || (res.data && res.data.ok===false)){
    out.textContent = (res.data && res.data.error) ? res.data.error : ("Error " + res.r.status);
    return;
  }

  const d = res.data || {};
  const o = d.order || {};
  const code = o.orderCode || o.orderId || o._id || "";
  const created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";
  const run = o.runDate ? new Date(o.runDate).toLocaleDateString() : "";

  let html = "";
  html += "<div class='row' style='justify-content:space-between;align-items:center;'>";
  html += "<div>";
  html += "<div style='font-weight:900;font-size:18px;'>Order <span class='code'>" + esc(code) + "</span></div>";
  html += "<div class='muted'>" + esc(created) + (run ? (" • Run: " + esc(run)) : "") + "</div>";
  html += "<div class='muted'>" + esc((d.user && d.user.name) ? d.user.name : "") + " (" + esc((d.user && d.user.email) ? d.user.email : "") + ")</div>";
  html += "</div>";
  html += "<div class='row'>";
  html += "<button class='btn' onclick='archiveOrder(" + JSON.stringify(String(d.user && d.user.id ? d.user.id : userId)) + "," + JSON.stringify(String(o.orderId || o._id || orderId)) + ")'>Archive</button>";
  html += "<button class='btn' onclick='deleteOrder(" + JSON.stringify(String(d.user && d.user.id ? d.user.id : userId)) + "," + JSON.stringify(String(o.orderId || o._id || orderId)) + ")'>Delete</button>";
  html += "</div>";
  html += "</div>";

  html += "<hr style='border:none;border-top:1px solid rgba(230,230,230,.10);margin:12px 0;'>";

  html += "<div class='row'>";
  html += "<span class='pill'>Status: <strong>" + esc(o.status || "submitted") + "</strong></span>";
  html += "<span class='pill'>Add-ons: <strong>" + esc(addOnsText(o)) + "</strong></span>";
  html += "</div>";

  html += "<details open><summary>Stores</summary>";
  html += "<div style='margin-top:8px;'><strong>Primary:</strong> " + esc(o.primaryStore || "") + "</div>";
  html += "<div><strong>Secondary:</strong> " + esc(o.secondaryStore || "") + "</div>";
  html += "</details>";

  html += "<details open><summary>Delivery</summary>";
  html += "<div style='margin-top:8px;'><strong>Community:</strong> " + esc(o.community || "") + "</div>";
  html += "<div><strong>Address:</strong> " + esc(o.streetAddress || "") + "</div>";
  html += "<div><strong>Phone:</strong> " + esc(o.phone || "") + "</div>";
  html += "</details>";

  html += "<details open><summary>Grocery List</summary>";
  html += "<pre>" + esc(o.groceryList || "") + "</pre>";
  html += "</details>";

  html += "<details><summary>Drop-off / Notes</summary>";
  html += "<pre>" + esc(o.notes || "") + "</pre>";
  html += "</details>";

  out.innerHTML = html;
}

load();
</script>
</body>
</html>`);
});

// /admin/picklist — simplified scan view
app.get("/admin/picklist", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Picklist</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--red:#E3342F;--bg:#0B0D10;--text:#E6E6E6;--muted:rgba(230,230,230,.72);--card:rgba(230,230,230,.06);--border:rgba(230,230,230,.14);}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);padding:14px;}
    a{color:var(--text);text-decoration:none;font-weight:800}
    a:hover{text-decoration:underline}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--text);font-weight:900;cursor:pointer}
    .btn.primary{background:var(--red);border-color:rgba(0,0,0,.2);color:#fff}
    .card{border:1px solid var(--border);border-radius:16px;background:var(--card);padding:12px;margin:12px 0}
    .muted{color:var(--muted)}
    pre{white-space:pre-wrap;background:rgba(0,0,0,.20);border:1px solid rgba(230,230,230,.10);padding:10px;border-radius:12px;overflow:auto}
    .hdr{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
    .code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;opacity:.95}
  </style>
</head>
<body>
  <div class="top">
    <a class="btn" href="/admin">← Back</a>
    <a class="btn" href="/admin/packing">Packing</a>
    <a class="btn" href="/api/admin/orders/export.csv">Export CSV</a>
    <a class="btn" href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
  </div>

  <div id="out">Loading…</div>

<script>
async function api(url, opts){
  const r = await fetch(url, Object.assign({ credentials:"include" }, opts || {}));
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { r:r, data:data, text:text };
}

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, function(c){
    return { "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;" }[c];
  });
}

function addOnsText(o){
  const add = (o && (o.addOns || o.addons)) ? (o.addOns || o.addons) : {};
  const parts = [];
  if(add.fastFood) parts.push("Fast Food");
  if(add.liquor) parts.push("Liquor");
  if(add.printing) parts.push("Printing");
  if(add.ride) parts.push("Ride");
  return parts.length ? parts.join(", ") : "None";
}

async function load(){
  const out = document.getElementById("out");
  out.textContent = "Loading…";

  const res = await api("/api/admin/orders");
  if(!res.r.ok || (res.data && res.data.ok===false)){
    out.textContent = (res.data && res.data.error) ? res.data.error : ("Error " + res.r.status);
    return;
  }

  const orders = (res.data && res.data.orders) ? res.data.orders : [];
  if(!orders.length){
    out.innerHTML = "<div class='muted'>No current orders.</div>";
    return;
  }

  let html = "";
  for(const o of orders){
    const userId = String(o.userId || "");
    const orderId = String(o.orderId || "");
    const detail = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId));
    if(!detail.r.ok || (detail.data && detail.data.ok===false)) continue;

    const d = detail.data || {};
    const ord = d.order || {};
    const code = ord.orderCode || ord.orderId || ord._id || "";
    const created = ord.createdAt ? new Date(ord.createdAt).toLocaleString() : "";

    html += "<div class='card'>";
    html += "<div class='hdr'>";
    html += "<div><strong>" + esc((d.user && d.user.name) ? d.user.name : "") + "</strong> <span class='muted'>(" + esc((d.user && d.user.email) ? d.user.email : "") + ")</span></div>";
    html += "<div class='muted'><span class='code'>" + esc(code) + "</span> • " + esc(created) + "</div>";
    html += "</div>";

    html += "<div style='margin-top:8px;'><strong>Primary:</strong> " + esc(ord.primaryStore || "") + "</div>";
    html += "<div><strong>Secondary:</strong> " + esc(ord.secondaryStore || "") + "</div>";
    html += "<div style='margin-top:8px;'><strong>Add-ons:</strong> " + esc(addOnsText(ord)) + "</div>";

    html += "<div style='margin-top:10px;'><strong>Grocery list:</strong></div>";
    html += "<pre>" + esc(ord.groceryList || "") + "</pre>";

    if(ord.notes){
      html += "<div style='margin-top:10px;'><strong>Drop-off / Notes:</strong></div>";
      html += "<pre>" + esc(ord.notes || "") + "</pre>";
    }

    html += "<div style='margin-top:10px;'><a href='/admin/order?userId=" + encodeURIComponent(userId) + "&orderId=" + encodeURIComponent(orderId) + "'>View full order →</a></div>";
    html += "</div>";
  }

  out.innerHTML = html || "<div class='muted'>No current orders.</div>";
}

load();
</script>
</body>
</html>`);
});

// /admin/packing — same idea; includes delivery + stores + list
app.get("/admin/packing", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Packing List</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--red:#E3342F;--bg:#0B0D10;--text:#E6E6E6;--muted:rgba(230,230,230,.72);--card:rgba(230,230,230,.06);--border:rgba(230,230,230,.14);}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);padding:14px;}
    a{color:var(--text);text-decoration:none;font-weight:800}
    a:hover{text-decoration:underline}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--text);font-weight:900;cursor:pointer}
    .btn.primary{background:var(--red);border-color:rgba(0,0,0,.2);color:#fff}
    .card{border:1px solid var(--border);border-radius:16px;background:var(--card);padding:12px;margin:12px 0}
    .muted{color:var(--muted)}
    pre{white-space:pre-wrap;background:rgba(0,0,0,.20);border:1px solid rgba(230,230,230,.10);padding:10px;border-radius:12px;overflow:auto}
    .hdr{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
    .code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;opacity:.95}
  </style>
</head>
<body>
  <div class="top">
    <a class="btn" href="/admin">← Back</a>
    <a class="btn" href="/admin/picklist">Picklist</a>
    <a class="btn" href="/api/admin/orders/export.csv">Export CSV</a>
    <a class="btn" href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
  </div>

  <div id="out">Loading…</div>

<script>
async function api(url, opts){
  const r = await fetch(url, Object.assign({ credentials:"include" }, opts || {}));
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { r:r, data:data, text:text };
}

function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, function(c){
    return { "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;" }[c];
  });
}

function addOnsText(o){
  const add = (o && (o.addOns || o.addons)) ? (o.addOns || o.addons) : {};
  const parts = [];
  if(add.fastFood) parts.push("Fast Food");
  if(add.liquor) parts.push("Liquor");
  if(add.printing) parts.push("Printing");
  if(add.ride) parts.push("Ride");
  return parts.length ? parts.join(", ") : "None";
}

async function load(){
  const out = document.getElementById("out");
  out.textContent = "Loading…";

  const res = await api("/api/admin/orders");
  if(!res.r.ok || (res.data && res.data.ok===false)){
    out.textContent = (res.data && res.data.error) ? res.data.error : ("Error " + res.r.status);
    return;
  }

  const orders = (res.data && res.data.orders) ? res.data.orders : [];
  if(!orders.length){
    out.innerHTML = "<div class='muted'>No current orders.</div>";
    return;
  }

  let html = "";
  for(const o of orders){
    const userId = String(o.userId || "");
    const orderId = String(o.orderId || "");
    const detail = await api("/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId));
    if(!detail.r.ok || (detail.data && detail.data.ok===false)) continue;

    const d = detail.data || {};
    const ord = d.order || {};
    const code = ord.orderCode || ord.orderId || ord._id || "";
    const created = ord.createdAt ? new Date(ord.createdAt).toLocaleString() : "";
    const run = ord.runDate ? new Date(ord.runDate).toLocaleDateString() : "";

    html += "<div class='card'>";
    html += "<div class='hdr'>";
    html += "<div><strong>" + esc((d.user && d.user.name) ? d.user.name : "") + "</strong> <span class='muted'>(" + esc((d.user && d.user.email) ? d.user.email : "") + ")</span></div>";
    html += "<div class='muted'><span class='code'>" + esc(code) + "</span> • " + esc(created) + (run ? (" • Run: " + esc(run)) : "") + "</div>";
    html += "</div>";

    html += "<div style='margin-top:8px;'><strong>Community:</strong> " + esc(ord.community || "") + "</div>";
    html += "<div><strong>Address:</strong> " + esc(ord.streetAddress || "") + "</div>";
    html += "<div><strong>Phone:</strong> " + esc(ord.phone || "") + "</div>";

    html += "<div style='margin-top:8px;'><strong>Primary:</strong> " + esc(ord.primaryStore || "") + "</div>";
    html += "<div><strong>Secondary:</strong> " + esc(ord.secondaryStore || "") + "</div>";
    html += "<div style='margin-top:8px;'><strong>Add-ons:</strong> " + esc(addOnsText(ord)) + "</div>";

    html += "<div style='margin-top:10px;'><strong>Grocery list:</strong></div>";
    html += "<pre>" + esc(ord.groceryList || "") + "</pre>";

    if(ord.notes){
      html += "<div style='margin-top:10px;'><strong>Drop-off / Notes:</strong></div>";
      html += "<pre>" + esc(ord.notes || "") + "</pre>";
    }

    html += "<div style='margin-top:10px;'><a href='/admin/order?userId=" + encodeURIComponent(userId) + "&orderId=" + encodeURIComponent(orderId) + "'>View full order →</a></div>";
    html += "</div>";
  }

  out.innerHTML = html || "<div class='muted'>No current orders.</div>";
}

load();
</script>
</body>
</html>`);
});

// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});