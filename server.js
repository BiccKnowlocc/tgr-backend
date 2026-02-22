/**
 * server.js — Tobermory Grocery Run backend (Express + MongoDB + Google OAuth + Square webhooks)
 *
 * IMPRESSIVE FUNCTIONALITY INCLUDED:
 * - Google sign-in: /auth/google + callback + /logout
 * - Robust sessions w/ MongoStore (no MemoryStore warnings)
 * - /api/me (frontend auth state)
 * - Run engine: /api/runs/active (cutoffs, slots, minimum-to-run)
 * - Orders:
 *    - POST /api/orders (multipart w/ optional file upload)
 *    - GET  /api/orders/:orderId (public status by Order ID)
 * - Server-truth fee estimator: POST /api/estimator
 * - Square links:
 *    - Membership checkout link resolver: POST /api/memberships/checkout
 *    - Payment link resolver: POST /api/payments/checkout
 *    - Convenience redirects: /pay/groceries, /pay/fees
 * - Member portal: /member (recent orders + pay buttons)
 * - Admin portal: /admin (search/filter, one-click status updates, CSV export, detail view, file download)
 * - Square webhooks: POST /webhooks/square (signature verified, idempotent, auto-sync membership)
 *
 * REQUIRED ENV (Render - backend service):
 * - SESSION_SECRET
 * - MONGO_URI (or MONGODB_URI)
 * - GOOGLE_CLIENT_ID
 * - GOOGLE_CLIENT_SECRET
 * - GOOGLE_CALLBACK_URL = https://api.tobermorygroceryrun.ca/auth/google/callback
 *
 * - SQUARE_LINK_STANDARD
 * - SQUARE_LINK_ROUTE
 * - SQUARE_LINK_ACCESS
 * - SQUARE_LINK_ACCESSPRO
 *
 * - SQUARE_PAY_GROCERIES_LINK
 * - SQUARE_PAY_FEES_LINK
 *
 * Square webhooks (for auto membership tracking):
 * - SQUARE_WEBHOOK_SIGNATURE_KEY
 * - SQUARE_WEBHOOK_NOTIFICATION_URL = https://api.tobermorygroceryrun.ca/webhooks/square
 * - SQUARE_ACCESS_TOKEN (Production token, used to retrieve customer email by customer_id)
 *
 * Plan variation mapping (from Catalog API):
 * - SQUARE_PLAN_STANDARD_VARIATION_ID
 * - SQUARE_PLAN_ROUTE_VARIATION_ID
 * - SQUARE_PLAN_ACCESS_VARIATION_ID
 * - SQUARE_PLAN_ACCESSPRO_VARIATION_ID
 *
 * OPTIONAL:
 * - TZ (default America/Toronto)
 * - ADMIN_EMAILS (comma-separated allowlist for /admin)
 */

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const MongoStorePkg = require("connect-mongo");
const MongoStore = MongoStorePkg.default || MongoStorePkg;

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const { Client, Environment, WebhooksHelper } = require("square");

const User = require("./models/User");

const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
const timezone = require("dayjs/plugin/timezone");
dayjs.extend(utc);
dayjs.extend(timezone);

// =========================
// ENV / CONFIG
// =========================
const PORT = process.env.PORT || 10000;

const MONGODB_URI =
  process.env.MONGODB_URI ||
  process.env.MONGO_URI ||
  "mongodb://127.0.0.1:27017/tgr";

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const TZ = process.env.TZ || "America/Toronto";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// Cookies across subdomains:
// If you ever need cross-site cookies on API subdomain, use SameSite=None + Secure.
// For now Lax is simplest.
const COOKIE_SAMESITE = "lax";
const COOKIE_DOMAIN = undefined;

const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
];

const SQUARE_LINKS = {
  standard: process.env.SQUARE_LINK_STANDARD,
  route: process.env.SQUARE_LINK_ROUTE,
  access: process.env.SQUARE_LINK_ACCESS,
  accesspro: process.env.SQUARE_LINK_ACCESSPRO,
};

const SQUARE_PAY_LINKS = {
  groceries: process.env.SQUARE_PAY_GROCERIES_LINK,
  fees: process.env.SQUARE_PAY_FEES_LINK,
};

// Square webhooks + customer lookup
const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL = process.env.SQUARE_WEBHOOK_NOTIFICATION_URL || "";
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";

// Map plan variation IDs -> internal tiers
const PLAN_MAP = {
  [process.env.SQUARE_PLAN_STANDARD_VARIATION_ID || ""]: "standard",
  [process.env.SQUARE_PLAN_ROUTE_VARIATION_ID || ""]: "route",
  [process.env.SQUARE_PLAN_ACCESS_VARIATION_ID || ""]: "access",
  [process.env.SQUARE_PLAN_ACCESSPRO_VARIATION_ID || ""]: "accesspro",
};

function squareClient() {
  return new Client({
    accessToken: SQUARE_ACCESS_TOKEN,
    environment: Environment.Production,
  });
}

// =========================
// App + middleware
// =========================
const app = express();

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
  })
);

// IMPORTANT: rawBody capture for Square signature verification
app.use(
  express.json({
    limit: "3mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("trust proxy", 1);

app.use(
  session({
    name: "tgr.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: true,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      ttl: 60 * 60 * 24 * 14,
    }),
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: COOKIE_SAMESITE,
      ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

// =========================
// Passport (Google OAuth)
// =========================
passport.serializeUser((user, done) => done(null, user._id.toString()));

passport.deserializeUser(async (id, done) => {
  try {
    const u = await User.findById(id).lean();
    done(null, u || null);
  } catch (e) {
    done(e);
  }
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_CALLBACK_URL) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email =
            (profile.emails && profile.emails[0] && profile.emails[0].value) || "";
          const normalized = String(email).toLowerCase().trim();
          if (!normalized) return done(null, false);

          const update = {
            googleId: profile.id,
            email: normalized,
            name: profile.displayName || "",
            photo:
              (profile.photos && profile.photos[0] && profile.photos[0].value) || "",
          };

          const u = await User.findOneAndUpdate(
            { email: normalized },
            {
              $set: update,
              $setOnInsert: {
                membershipLevel: "none",
                membershipStatus: "inactive",
                renewalDate: null,
                discounts: [],
                perks: [],
                profile: { version: 1, defaultId: "", addresses: [] },
              },
            },
            { upsert: true, new: true }
          );

          return done(null, u);
        } catch (e) {
          return done(e);
        }
      }
    )
  );
}

app.use(passport.initialize());
app.use(passport.session());

// =========================
// Uploads
// =========================
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 },
});

// =========================
// Pricing (server truth baseline)
// =========================
const PRICING = {
  serviceFee: 25,
  zone: { A: 20, B: 15, C: 10, D: 25 },
  owenRunFeePerOrder: 20,

  addOns: {
    extraStore: 8,
    parcelDrop: 10,
    parcelBulkyExtra: 8,
    liquor: 12,
    fastFood: 10,
    waitPerBlock: 10,
    rideSeat: 45,
    rideSeatSouthOfFerndale: 30,
    bulkyPerItem: 18,
    printingBase: 5,
    printingFirst10: 1.25,
    printingAfter10: 0.75,
  },

  groceryUnderMin: { threshold: 35, surcharge: 19 },
};

function calcPrinting(pages) {
  const p = Number(pages || 0);
  if (p <= 0) return 0;
  const first = Math.min(p, 10);
  const rest = Math.max(0, p - 10);
  return (
    PRICING.addOns.printingBase +
    first * PRICING.addOns.printingFirst10 +
    rest * PRICING.addOns.printingAfter10
  );
}

// estimator-only
function membershipDiscounts(tier, applyPerkYes) {
  if (!tier || !applyPerkYes)
    return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false };

  if (tier === "standard")
    return { serviceOff: 0, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };

  if (tier === "route")
    return { serviceOff: 5, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };

  if (tier === "access")
    return { serviceOff: 8, zoneOff: 10, freeAddonUpTo: 10, waitWaived: true };

  if (tier === "accesspro")
    return { serviceOff: 10, zoneOff: 0, freeAddonUpTo: 0, waitWaived: true };

  return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false };
}

// =========================
// Mongo models
// =========================
const CounterSchema = new mongoose.Schema(
  { key: { type: String, unique: true }, seq: { type: Number, default: 0 } },
  { timestamps: true }
);

const RunSchema = new mongoose.Schema(
  {
    runKey: { type: String, unique: true },
    type: { type: String, enum: ["local", "owen"], required: true },
    opensAt: { type: Date, required: true },
    cutoffAt: { type: Date, required: true },
    maxSlots: { type: Number, default: 12 },

    minOrders: { type: Number, default: 6 },
    minFees: { type: Number, default: 0 },
    minLogic: { type: String, enum: ["OR", "AND"], default: "OR" },

    bookedOrdersCount: { type: Number, default: 0 },
    bookedFeesTotal: { type: Number, default: 0 },

    lastRecalcAt: { type: Date },
  },
  { timestamps: true }
);

const OrderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true, index: true },

    runKey: { type: String, required: true },
    runType: { type: String, enum: ["local", "owen"], required: true },

    customer: { fullName: String, email: String, phone: String },

    address: {
      town: String,
      streetAddress: String,
      zone: { type: String, enum: ["A", "B", "C", "D"] },
    },

    stores: { primary: String, extra: [String] },

    preferences: {
      dropoffPref: String,
      subsPref: String,
      contactPref: String,
      contactAuth: Boolean,
    },

    list: {
      groceryListText: String,
      attachment: { originalName: String, mimeType: String, size: Number, path: String },
    },

    consents: { terms: Boolean, accuracy: Boolean, dropoff: Boolean },

    pricingSnapshot: {
      serviceFee: Number,
      zoneFee: Number,
      runFee: Number,
      addOnsFees: Number,
      surcharges: Number,
      discount: Number,
      totalFees: Number,
    },

    status: {
      state: { type: String, default: "submitted" },
      note: { type: String, default: "" },
      updatedAt: { type: Date, default: Date.now },
      updatedBy: { type: String, default: "system" },
    },
  },
  { timestamps: true }
);

// Webhook idempotency store
const WebhookEventSchema = new mongoose.Schema(
  { eventId: { type: String, unique: true, index: true }, type: { type: String, default: "" } },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const WebhookEvent = mongoose.model("WebhookEvent", WebhookEventSchema);

// =========================
// Helpers
// =========================
function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function nowTz() {
  return dayjs().tz(TZ);
}

function fmtLocal(d) {
  if (!d) return "";
  return dayjs(d).tz(TZ).format("ddd MMM D, h:mma");
}

function nextDow(targetDow, from) {
  let d = dayjs(from).tz(TZ);
  const current = d.day();
  let diff = (targetDow - current + 7) % 7;
  if (diff === 0) diff = 7;
  return d.add(diff, "day");
}

function buildRunTimes(type) {
  const base = nowTz();
  if (type === "local") {
    const delivery = nextDow(6, base); // Saturday
    const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0); // Thu 6pm
    const opens = delivery.subtract(5, "day").hour(0).minute(0).second(0).millisecond(0); // Mon 12am
    return { delivery, cutoff, opens };
  }
  const delivery = nextDow(0, base); // Sunday
  const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0); // Fri 6pm
  const opens = delivery.subtract(6, "day").hour(0).minute(0).second(0).millisecond(0); // Mon 12am
  return { delivery, cutoff, opens };
}

function runMinimumConfig(type) {
  if (type === "local") {
    return { minOrders: 6, minFees: 200, minLogic: "OR", minimumText: "Minimum: 6 orders OR $200 booked fees" };
  }
  return { minOrders: 6, minFees: 300, minLogic: "AND", minimumText: "Minimum: 6 orders AND $300 booked fees" };
}

function meetsMinimums(run) {
  if (run.minLogic === "AND") {
    return run.bookedOrdersCount >= run.minOrders && run.bookedFeesTotal >= run.minFees;
  }
  return run.bookedOrdersCount >= run.minOrders || run.bookedFeesTotal >= run.minFees;
}

async function ensureUpcomingRuns() {
  const out = {};
  for (const type of ["local", "owen"]) {
    const { delivery, cutoff, opens } = buildRunTimes(type);
    const runKey = delivery.format("YYYY-MM-DD") + "-" + type;

    let run = await Run.findOne({ runKey }).lean();
    if (!run) {
      const cfg = runMinimumConfig(type);
      const created = await Run.create({
        runKey,
        type,
        opensAt: opens.toDate(),
        cutoffAt: cutoff.toDate(),
        maxSlots: 12,
        minOrders: cfg.minOrders,
        minFees: cfg.minFees,
        minLogic: cfg.minLogic,
      });
      run = created.toObject();
    }

    const needsRecalc =
      !run.lastRecalcAt ||
      dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(2, "minute").toDate());

    if (needsRecalc) {
      const agg = await Order.aggregate([
        { $match: { runKey } },
        { $group: { _id: "$runKey", c: { $sum: 1 }, fees: { $sum: "$pricingSnapshot.totalFees" } } },
      ]);
      const c = agg?.[0]?.c || 0;
      const fees = agg?.[0]?.fees || 0;
      await Run.updateOne(
        { runKey },
        { $set: { bookedOrdersCount: c, bookedFeesTotal: fees, lastRecalcAt: new Date() } }
      );
      run.bookedOrdersCount = c;
      run.bookedFeesTotal = fees;
      run.lastRecalcAt = new Date();
    }

    out[type] = run;
  }
  return out;
}

async function nextOrderId() {
  const c = await Counter.findOneAndUpdate(
    { key: "orders" },
    { $inc: { seq: 1 } },
    { upsert: true, new: true }
  ).lean();
  const num = String(c.seq).padStart(5, "0");
  return "TGR-" + num;
}

function safeJsonArray(str) {
  try {
    const v = JSON.parse(str || "[]");
    if (Array.isArray(v)) return v.map((x) => String(x || "").trim()).filter(Boolean);
    return [];
  } catch {
    return [];
  }
}

function computeFeeBreakdown(input) {
  const zone = String(input.zone || "");
  const runType = String(input.runType || "local");

  const extraStores = Array.isArray(input.extraStores)
    ? input.extraStores.map(String).map(s => s.trim()).filter(Boolean)
    : safeJsonArray(input.extraStoresJson);

  const pages = Math.max(0, Number(input.printPages || 0));
  const grocerySubtotal = Math.max(0, Number(input.grocerySubtotal || 0));

  const memberTier = String(input.memberTier || "");
  const applyPerk = String(input.applyPerk || "yes") === "yes";
  const disc = membershipDiscounts(memberTier, applyPerk);

  const serviceFee = PRICING.serviceFee;
  const zoneFee = PRICING.zone[zone] || 0;
  const runFee = runType === "owen" ? PRICING.owenRunFeePerOrder : 0;

  const lineItems = [];
  lineItems.push({ label: "Service fee", amount: serviceFee });
  if (zoneFee > 0) lineItems.push({ label: `Zone fee (${zone})`, amount: zoneFee });
  if (runFee > 0) lineItems.push({ label: "Owen Sound run fee", amount: runFee });

  let addOnsFees = 0;

  if (extraStores.length) {
    const amt = extraStores.length * PRICING.addOns.extraStore;
    addOnsFees += amt;
    lineItems.push({ label: `Extra store stops (${extraStores.length})`, amount: amt });
  }

  if (String(input.addon_printing || "") === "yes" && pages > 0) {
    const amt = calcPrinting(pages);
    addOnsFees += amt;
    lineItems.push({ label: `Printing (${pages} pages)`, amount: amt });
  }

  let surcharges = 0;
  if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) {
    surcharges += PRICING.groceryUnderMin.surcharge;
    lineItems.push({
      label: `Small order surcharge (grocery subtotal under $${PRICING.groceryUnderMin.threshold})`,
      amount: PRICING.groceryUnderMin.surcharge,
    });
  }

  // Membership discount logic: serviceOff + best-of (zoneOff OR free-addon-up-to against add-ons+run)
  const serviceOff = Math.min(serviceFee, disc.serviceOff || 0);
  const optionA = Math.min(zoneFee, disc.zoneOff || 0);
  const optionB = Math.min(addOnsFees + runFee, disc.freeAddonUpTo || 0);
  const bestOr = Math.max(optionA, optionB);
  const discount = serviceOff + bestOr;

  if (discount > 0) lineItems.push({ label: "Membership discount/perk (estimated)", amount: -discount });

  const totalFees = Math.max(0, serviceFee + zoneFee + runFee + addOnsFees + surcharges - discount);

  return {
    lineItems,
    totals: { serviceFee, zoneFee, runFee, addOnsFees, surcharges, discount, totalFees },
  };
}

// =========================
// Guards
// =========================
function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).send("Sign-in required.");
  next();
}

function requireAdmin(req, res, next) {
  const email = String(req.user?.email || "").toLowerCase();
  if (!email) return res.status(403).send("Admin access required.");
  if (ADMIN_EMAILS.length && !ADMIN_EMAILS.includes(email)) return res.status(403).send("Admin access required.");
  next();
}

// =========================
// Auth routes
// =========================
app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
    return res.status(500).send("Google auth is not configured on this server.");
  }
  const returnTo = String(req.query.returnTo || "https://tobermorygroceryrun.ca/").trim();
  req.session.returnTo = returnTo;
  return passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "https://tobermorygroceryrun.ca/?login=failed" }),
  (req, res) => {
    const rt = req.session.returnTo || "https://tobermorygroceryrun.ca/";
    delete req.session.returnTo;
    res.redirect(rt);
  }
);

app.get("/logout", (req, res) => {
  const returnTo = String(req.query.returnTo || "https://tobermorygroceryrun.ca/").trim();
  req.session.destroy(() => res.redirect(returnTo));
});

app.get("/api/me", (req, res) => {
  const u = req.user;
  res.json({
    ok: true,
    loggedIn: !!u,
    email: u?.email || null,
    name: u?.name || "",
    membershipLevel: u?.membershipLevel || "none",
    membershipStatus: u?.membershipStatus || "inactive",
    renewalDate: u?.renewalDate || null,
  });
});

// =========================
// Health
// =========================
app.get("/health", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// =========================
// Square link resolvers + convenience redirects
// =========================
app.post("/api/memberships/checkout", (req, res) => {
  const tier = String(req.body?.tier || "").trim().toLowerCase();
  const allowed = new Set(["standard", "route", "access", "accesspro"]);
  if (!allowed.has(tier)) return res.status(400).json({ ok: false, error: "Invalid tier" });

  const url = SQUARE_LINKS[tier];
  if (!url) return res.status(500).json({ ok: false, error: `Missing Square link: SQUARE_LINK_${tier.toUpperCase()}` });

  res.json({ ok: true, tier, checkoutUrl: url });
});

app.post("/api/payments/checkout", (req, res) => {
  const kind = String(req.body?.kind || "").trim().toLowerCase();
  const allowed = new Set(["groceries", "fees"]);
  if (!allowed.has(kind)) return res.status(400).json({ ok: false, error: "Invalid payment kind" });

  const url = SQUARE_PAY_LINKS[kind];
  if (!url) {
    const envKey = kind === "groceries" ? "SQUARE_PAY_GROCERIES_LINK" : "SQUARE_PAY_FEES_LINK";
    return res.status(500).json({ ok: false, error: `Missing Render env var ${envKey}` });
  }
  res.json({ ok: true, kind, checkoutUrl: url });
});

app.get("/pay/groceries", (req, res) => {
  const url = SQUARE_PAY_LINKS.groceries;
  if (!url) return res.status(500).send("Payment link not configured (SQUARE_PAY_GROCERIES_LINK).");
  res.redirect(url);
});

app.get("/pay/fees", (req, res) => {
  const url = SQUARE_PAY_LINKS.fees;
  if (!url) return res.status(500).send("Payment link not configured (SQUARE_PAY_FEES_LINK).");
  res.redirect(url);
});

// =========================
// Runs
// =========================
app.get("/api/runs/active", async (req, res) => {
  try {
    const runs = await ensureUpcomingRuns();
    const now = nowTz();
    const out = {};

    for (const type of ["local", "owen"]) {
      const run = runs[type];
      const opensAt = dayjs(run.opensAt).tz(TZ);
      const cutoffAt = dayjs(run.cutoffAt).tz(TZ);

      const windowOpen = now.isAfter(opensAt) && now.isBefore(cutoffAt);
      const slotsRemaining = Math.max(0, (run.maxSlots || 12) - (run.bookedOrdersCount || 0));
      const minCfg = runMinimumConfig(type);

      out[type] = {
        runKey: run.runKey,
        type: run.type,
        maxSlots: run.maxSlots || 12,
        bookedOrdersCount: run.bookedOrdersCount || 0,
        bookedFeesTotal: run.bookedFeesTotal || 0,
        slotsRemaining,
        isOpen: windowOpen && slotsRemaining > 0,
        opensAtLocal: fmtLocal(run.opensAt),
        cutoffAtLocal: fmtLocal(run.cutoffAt),
        meetsMinimums: meetsMinimums(run),
        minimumText: minCfg.minimumText,
      };
    }

    res.json({ ok: true, runs: out });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// Fee estimator (server truth)
// =========================
app.post("/api/estimator", (req, res) => {
  try {
    const b = req.body || {};
    const breakdown = computeFeeBreakdown(b);
    res.json({ ok: true, breakdown });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// Orders
// =========================
app.post("/api/orders", upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};

    const required = [
      "fullName","email","phone","town","streetAddress","zone","runType",
      "primaryStore","groceryList","dropoffPref","subsPref","contactPref",
    ];
    for (const k of required) {
      const v = String(b[k] || "").trim();
      if (!v) return res.status(400).json({ ok: false, error: "Missing required field: " + k });
    }

    if (String(b.contactAuth || "") !== "yes") {
      return res.status(400).json({ ok: false, error: "Contact authorization is required." });
    }

    if (
      String(b.consent_terms || "") !== "yes" ||
      String(b.consent_accuracy || "") !== "yes" ||
      String(b.consent_dropoff || "") !== "yes"
    ) {
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    const runs = await ensureUpcomingRuns();
    const runType = String(b.runType || "");
    const run = runs[runType];
    if (!run) return res.status(400).json({ ok: false, error: "Invalid runType." });

    const now = nowTz();
    const opensAt = dayjs(run.opensAt).tz(TZ);
    const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    const windowOpen = now.isAfter(opensAt) && now.isBefore(cutoffAt);
    if (!windowOpen) return res.status(403).json({ ok: false, error: "Ordering is closed for this run." });

    const maxSlots = run.maxSlots || 12;

    const orderId = await nextOrderId();

    let attachment = null;
    if (req.file) {
      attachment = {
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: req.file.path,
      };
    }

    const extraStores = safeJsonArray(b.extraStores);

    // Server-truth pricing snapshot (estimator fields you collect on index page)
    const breakdown = computeFeeBreakdown({
      zone: b.zone,
      runType: b.runType,
      extraStores: extraStores,
      grocerySubtotal: Number(b.grocerySubtotal || 0),
      memberTier: b.memberTier || "",
      applyPerk: b.applyPerk || "yes",
      addon_printing: b.addon_printing || "no",
      printPages: Number(b.printPages || 0),
    });

    const pricingSnapshot = breakdown.totals;

    const orderDoc = {
      orderId,
      runKey: run.runKey,
      runType,

      customer: {
        fullName: String(b.fullName || "").trim(),
        email: String(b.email || "").trim().toLowerCase(),
        phone: String(b.phone || "").trim(),
      },

      address: {
        town: String(b.town || "").trim(),
        streetAddress: String(b.streetAddress || "").trim(),
        zone: String(b.zone || ""),
      },

      stores: {
        primary: String(b.primaryStore || "").trim(),
        extra: extraStores,
      },

      preferences: {
        dropoffPref: String(b.dropoffPref || ""),
        subsPref: String(b.subsPref || ""),
        contactPref: String(b.contactPref || ""),
        contactAuth: true,
      },

      list: {
        groceryListText: String(b.groceryList || "").trim(),
        attachment,
      },

      consents: { terms: true, accuracy: true, dropoff: true },
      pricingSnapshot,

      status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" },
    };

    // Slot gate + update run counters atomically
    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedOrdersCount: { $lt: maxSlots } },
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees }, $set: { lastRecalcAt: new Date() } },
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    try {
      await Order.create(orderDoc);
    } catch (e) {
      await Run.updateOne(
        { runKey: run.runKey },
        { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -pricingSnapshot.totalFees }, $set: { lastRecalcAt: new Date() } }
      );
      throw e;
    }

    res.json({ ok: true, orderId, runKey: run.runKey });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/orders/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim();
    if (!orderId) return res.status(400).json({ ok: false, error: "Missing orderId" });

    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    res.json({
      ok: true,
      order: {
        orderId: order.orderId,
        createdAtLocal: fmtLocal(order.createdAt),
        stores: order.stores,
        address: order.address,
        pricingSnapshot: order.pricingSnapshot,
        status: {
          state: order.status?.state || "submitted",
          note: order.status?.note || "",
          updatedAtLocal: fmtLocal(order.status?.updatedAt || order.updatedAt),
        },
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// Member portal (clean + useful)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = req.user;
  const email = String(u?.email || "").toLowerCase();

  const orders = await Order.find({ "customer.email": email })
    .sort({ createdAt: -1 })
    .limit(25)
    .lean();

  const rows = orders
    .map((o) => {
      const status = o.status?.state || "submitted";
      const when = fmtLocal(o.createdAt);
      const primary = o.stores?.primary || "—";
      const town = o.address?.town || "—";
      const fees =
        typeof o.pricingSnapshot?.totalFees === "number"
          ? o.pricingSnapshot.totalFees.toFixed(2)
          : "0.00";

      return `
        <tr>
          <td style="padding:10px 8px;border-top:1px solid #ddd;font-weight:900;">${escapeHtml(o.orderId)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(when)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(primary)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(town)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;font-weight:900;">${escapeHtml(status)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">$${escapeHtml(fees)}</td>
        </tr>
      `;
    })
    .join("");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Member Portal</title>
</head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:1100px;margin:0 auto;">
  <h1 style="margin:0 0 6px;">Member Portal</h1>
  <div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(email)}</strong></div>

  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
    <a href="https://tobermorygroceryrun.ca/" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Back to site</a>
    <a href="/pay/groceries" style="padding:12px 14px;border:1px solid #e3342f;background:#e3342f;color:#fff;border-radius:12px;text-decoration:none;font-weight:900;">Pay Grocery Total</a>
    <a href="/pay/fees" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Pay Service & Delivery Fees</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
  </div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Account</h2>
    <div><strong>Name:</strong> ${escapeHtml(u?.name || "—")}</div>
    <div><strong>Membership level:</strong> ${escapeHtml(u?.membershipLevel || "none")}</div>
    <div><strong>Membership status:</strong> ${escapeHtml(u?.membershipStatus || "inactive")}</div>
    <div><strong>Renewal date:</strong> ${escapeHtml(u?.renewalDate ? String(u.renewalDate) : "—")}</div>
    <div style="color:#666;margin-top:8px;">Membership status is auto-synced from Square webhook events.</div>
  </div>

  <h2 style="margin:0 0 8px;">Recent orders</h2>
  <table style="width:100%;border-collapse:collapse;">
    <thead>
      <tr>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Order ID</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Created</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Store</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Town</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Status</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Fees</th>
      </tr>
    </thead>
    <tbody>
      ${rows || `<tr><td colspan="6" style="padding:10px 8px;color:#666;">No orders yet.</td></tr>`}
    </tbody>
  </table>
</body></html>`);
});

// =========================
// Admin portal: list, filter, status updates, CSV, detail, file download
// =========================
function csvEscape(val) {
  const s = String(val ?? "");
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildAdminOrderQuery(q, status) {
  const query = {};
  const qq = String(q || "").trim();
  const st = String(status || "").trim().toLowerCase();
  if (st && st !== "all") query["status.state"] = st;

  if (qq) {
    query["$or"] = [
      { orderId: new RegExp(qq, "i") },
      { "customer.fullName": new RegExp(qq, "i") },
      { "customer.email": new RegExp(qq, "i") },
      { "customer.phone": new RegExp(qq, "i") },
      { "address.town": new RegExp(qq, "i") },
      { "stores.primary": new RegExp(qq, "i") },
    ];
  }
  return query;
}

app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  const q = String(req.query.q || "");
  const status = String(req.query.status || "all");
  const mongoQuery = buildAdminOrderQuery(q, status);

  const orders = await Order.find(mongoQuery).sort({ createdAt: -1 }).limit(200).lean();
  const statusSel = (v) => (String(status).toLowerCase() === v ? "selected" : "");
  const returnToBase = "/admin?" + new URLSearchParams({ q, status }).toString();
  const csvUrl = "/admin/orders.csv" + (q || status ? `?${new URLSearchParams({ q, status }).toString()}` : "");

  const rows = orders
    .map((o) => {
      const st = o.status?.state || "submitted";
      const when = fmtLocal(o.createdAt);
      const name = o.customer?.fullName || "—";
      const phone = o.customer?.phone || "—";
      const email = o.customer?.email || "—";
      const town = o.address?.town || "—";
      const runType = o.runType || "—";
      const totalFees =
        typeof o.pricingSnapshot?.totalFees === "number"
          ? o.pricingSnapshot.totalFees.toFixed(2)
          : "0.00";

      return `
        <tr>
          <td style="padding:10px 8px;border-top:1px solid #ddd;font-weight:900;">
            <a href="/admin/orders/${encodeURIComponent(o.orderId)}" style="color:#e3342f;text-decoration:none;">${escapeHtml(o.orderId)}</a>
          </td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(when)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(runType)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">
            ${escapeHtml(name)}
            <div style="color:#666;font-size:12px;">${escapeHtml(phone)} • ${escapeHtml(email)}</div>
          </td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(town)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">$${escapeHtml(totalFees)}</td>
          <td style="padding:10px 8px;border-top:1px solid #ddd;">
            <div style="font-weight:900;margin-bottom:6px;">${escapeHtml(st)}</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              ${["submitted","paid","delivered","issue"].map(s => `
                <form method="POST" action="/admin/orders/${encodeURIComponent(o.orderId)}/status" style="margin:0;">
                  <input type="hidden" name="state" value="${s}">
                  <input type="hidden" name="returnTo" value="${escapeHtml(returnToBase)}">
                  <button style="padding:8px 10px;border:1px solid #ddd;border-radius:10px;cursor:pointer;background:${s===st?"#e3342f":"#fff"};color:${s===st?"#fff":"#111"};font-weight:900;">
                    ${s}
                  </button>
                </form>
              `).join("")}
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Admin</title>
</head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:1280px;margin:0 auto;">
  <h1 style="margin:0 0 6px;">Admin</h1>
  <div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(req.user?.email || "")}</strong></div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <form method="GET" action="/admin" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end;margin:0;">
      <div style="flex:1;min-width:240px;">
        <label style="display:block;font-weight:900;margin:0 0 6px;">Search</label>
        <input name="q" value="${escapeHtml(q)}" placeholder="Order ID, name, phone, town, store..." style="width:100%;padding:12px;border:1px solid #ddd;border-radius:12px;">
      </div>
      <div style="min-width:200px;">
        <label style="display:block;font-weight:900;margin:0 0 6px;">Status</label>
        <select name="status" style="width:100%;padding:12px;border:1px solid #ddd;border-radius:12px;">
          <option value="all" ${statusSel("all")}>All</option>
          <option value="submitted" ${statusSel("submitted")}>submitted</option>
          <option value="paid" ${statusSel("paid")}>paid</option>
          <option value="delivered" ${statusSel("delivered")}>delivered</option>
          <option value="issue" ${statusSel("issue")}>issue</option>
        </select>
      </div>
      <button style="padding:12px 14px;border:1px solid #e3342f;background:#e3342f;color:#fff;border-radius:12px;font-weight:900;cursor:pointer;">Apply</button>
      <a href="${csvUrl}" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Download CSV</a>
      <a href="/pay/fees" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Fees link</a>
      <a href="/pay/groceries" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Groceries link</a>
      <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
    </form>
    <div style="color:#666;margin-top:10px;">Showing latest 200 results. Click an Order ID for print-friendly details + file download.</div>
  </div>

  <table style="width:100%;border-collapse:collapse;">
    <thead>
      <tr>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Order ID</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Created</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Run</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Customer</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Town</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Fees</th>
        <th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Status</th>
      </tr>
    </thead>
    <tbody>
      ${rows || `<tr><td colspan="7" style="padding:10px 8px;color:#666;">No orders found.</td></tr>`}
    </tbody>
  </table>
</body></html>`);
});

app.post("/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  const orderId = String(req.params.orderId || "").trim();
  const state = String(req.body?.state || "").trim().toLowerCase();
  const returnTo = String(req.body?.returnTo || "/admin").trim();

  const allowed = new Set(["submitted", "paid", "delivered", "issue"]);
  if (!allowed.has(state)) return res.status(400).send("Invalid state");

  await Order.updateOne(
    { orderId },
    {
      $set: {
        "status.state": state,
        "status.updatedAt": new Date(),
        "status.updatedBy": String(req.user?.email || "admin"),
      },
    }
  );

  res.redirect(returnTo || "/admin");
});

app.get("/admin/orders.csv", requireLogin, requireAdmin, async (req, res) => {
  const q = String(req.query.q || "");
  const status = String(req.query.status || "all");
  const mongoQuery = buildAdminOrderQuery(q, status);

  const orders = await Order.find(mongoQuery).sort({ createdAt: -1 }).limit(2000).lean();

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="tgr-orders.csv"`);

  const header = [
    "orderId","createdAtLocal","runType","status",
    "customerName","customerEmail","customerPhone",
    "town","primaryStore","extraStores","totalFees"
  ].join(",");

  const lines = orders.map(o => {
    const createdAtLocal = fmtLocal(o.createdAt);
    const totalFees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
    return [
      csvEscape(o.orderId),
      csvEscape(createdAtLocal),
      csvEscape(o.runType || ""),
      csvEscape(o.status?.state || ""),
      csvEscape(o.customer?.fullName || ""),
      csvEscape(o.customer?.email || ""),
      csvEscape(o.customer?.phone || ""),
      csvEscape(o.address?.town || ""),
      csvEscape(o.stores?.primary || ""),
      csvEscape((o.stores?.extra || []).join(" | ")),
      csvEscape(totalFees),
    ].join(",");
  });

  res.send([header, ...lines].join("\n"));
});

app.get("/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  const orderId = String(req.params.orderId || "").trim();
  const o = await Order.findOne({ orderId }).lean();
  if (!o) return res.status(404).send("Order not found");

  const st = o.status?.state || "submitted";
  const when = fmtLocal(o.createdAt);
  const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
  const extra = (o.stores?.extra || []).join(", ") || "—";
  const file = o.list?.attachment;

  const fileBlock = file
    ? `<div style="margin-top:10px;">
         <strong>Uploaded file:</strong> ${escapeHtml(file.originalName || "file")}
         <div style="margin-top:6px;">
           <a href="/admin/orders/${encodeURIComponent(orderId)}/file" style="color:#e3342f;font-weight:900;">Download</a>
         </div>
       </div>`
    : `<div style="margin-top:10px;color:#666;">No file uploaded.</div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Order ${escapeHtml(orderId)}</title>
</head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:980px;margin:0 auto;">
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
    <a href="/admin" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Back to admin</a>
    <a href="javascript:window.print()" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Print</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
  </div>

  <h1 style="margin:0 0 6px;">${escapeHtml(orderId)}</h1>
  <div style="color:#444;margin-bottom:14px;">Created: ${escapeHtml(when)} • Status: <strong>${escapeHtml(st)}</strong> • Fees: <strong>$${escapeHtml(fees)}</strong></div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Customer</h2>
    <div><strong>Name:</strong> ${escapeHtml(o.customer?.fullName || "—")}</div>
    <div><strong>Email:</strong> ${escapeHtml(o.customer?.email || "—")}</div>
    <div><strong>Phone:</strong> ${escapeHtml(o.customer?.phone || "—")}</div>
  </div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Address</h2>
    <div><strong>Town:</strong> ${escapeHtml(o.address?.town || "—")}</div>
    <div><strong>Street:</strong> ${escapeHtml(o.address?.streetAddress || "—")}</div>
    <div><strong>Zone:</strong> ${escapeHtml(o.address?.zone || "—")}</div>
  </div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Stores</h2>
    <div><strong>Primary:</strong> ${escapeHtml(o.stores?.primary || "—")}</div>
    <div><strong>Extra:</strong> ${escapeHtml(extra)}</div>
  </div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Preferences</h2>
    <div><strong>Drop-off:</strong> ${escapeHtml(o.preferences?.dropoffPref || "—")}</div>
    <div><strong>Substitutions:</strong> ${escapeHtml(o.preferences?.subsPref || "—")}</div>
    <div><strong>Contact:</strong> ${escapeHtml(o.preferences?.contactPref || "—")}</div>
  </div>

  <div style="border:1px solid #ddd;border-radius:14px;padding:14px;margin-bottom:14px;">
    <h2 style="margin:0 0 8px;">Grocery list</h2>
    <pre style="white-space:pre-wrap;margin:0;background:#fafafa;border:1px solid #eee;border-radius:12px;padding:12px;">${escapeHtml(o.list?.groceryListText || "")}</pre>
    ${fileBlock}
  </div>
</body></html>`);
});

app.get("/admin/orders/:orderId/file", requireLogin, requireAdmin, async (req, res) => {
  const orderId = String(req.params.orderId || "").trim();
  const o = await Order.findOne({ orderId }).lean();
  if (!o) return res.status(404).send("Order not found");

  const file = o.list?.attachment;
  if (!file || !file.path) return res.status(404).send("No file uploaded");

  const abs = path.resolve(file.path);
  if (!fs.existsSync(abs)) return res.status(404).send("File missing on server");

  res.download(abs, file.originalName || "attachment");
});

// =========================
// Square Webhook: auto-sync membership
// =========================
app.post("/webhooks/square", async (req, res) => {
  try {
    const signatureHeader = req.get("x-square-hmacsha256-signature") || "";
    const body = req.rawBody || "";

    if (!SQUARE_WEBHOOK_SIGNATURE_KEY || !SQUARE_WEBHOOK_NOTIFICATION_URL) {
      return res.status(500).send("Square webhook env not configured.");
    }

    const valid = await WebhooksHelper.verifySignature({
      requestBody: body,
      signatureHeader,
      signatureKey: SQUARE_WEBHOOK_SIGNATURE_KEY,
      notificationUrl: SQUARE_WEBHOOK_NOTIFICATION_URL,
    });

    if (!valid) return res.status(403).send("Invalid signature");

    const evt = req.body || {};
    const eventId = String(evt.event_id || "");
    const eventType = String(evt.type || "");
    const subscription = evt?.data?.object?.subscription;

    // idempotent deliveries
    if (eventId) {
      const exists = await WebhookEvent.findOne({ eventId }).lean();
      if (exists) return res.status(200).send("ok");
      await WebhookEvent.create({ eventId, type: eventType });
    }

    // only subscription events
    if ((eventType !== "subscription.created" && eventType !== "subscription.updated") || !subscription) {
      return res.status(200).send("ok");
    }

    const customerId = String(subscription.customer_id || "");
    const planVariationId = String(subscription.plan_variation_id || "");
    const sqStatus = String(subscription.status || "").toUpperCase();

    const tier = PLAN_MAP[planVariationId] || "none";

    const internalStatus =
      sqStatus === "ACTIVE" ? "active" :
      (sqStatus === "CANCELED" || sqStatus === "CANCELLED") ? "cancelled" :
      (sqStatus === "PAUSED") ? "inactive" :
      "inactive";

    const renewalDate = subscription.charged_through_date ? new Date(subscription.charged_through_date) : null;

    // 1) match by previously stored square customer id
    let user = await User.findOne({ "profile.squareCustomerId": customerId });

    // 2) fallback: lookup Square customer -> match email -> store squareCustomerId
    if (!user) {
      if (!SQUARE_ACCESS_TOKEN) return res.status(200).send("ok");

      const client = squareClient();
      const resp = await client.customersApi.retrieveCustomer(customerId);
      const cust = resp?.result?.customer;

      const email = String(cust?.emailAddress || "").toLowerCase().trim();
      if (!email) return res.status(200).send("ok");

      user = await User.findOne({ email });
      if (!user) return res.status(200).send("ok");

      await User.updateOne(
        { _id: user._id },
        { $set: { "profile.squareCustomerId": customerId, "profile.squareCustomerEmail": email } }
      );
    }

    const set = { membershipStatus: internalStatus };
    if (tier !== "none") set.membershipLevel = tier;
    if (renewalDate) set.renewalDate = renewalDate;

    await User.updateOne({ _id: user._id }, { $set: set });

    return res.status(200).send("ok");
  } catch (e) {
    return res.status(500).send("webhook error: " + String(e));
  }
});

// =========================
// Root
// =========================
app.get("/", (req, res) => res.send("TGR backend up"));

// =========================
// Boot
// =========================
async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");
  app.listen(PORT, () => console.log("Server running on port", PORT));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});