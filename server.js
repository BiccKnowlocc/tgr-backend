// ======= server.js (FULL FILE) — TGR backend =======
// Implements: Google OAuth, required profile onboarding, runs (biweekly), estimator, orders, cancel tokens
// + FULL admin UI and admin endpoints (search/status/cancel/delete/export)
// + MEMBER PORTAL (/member) + order list + cancel button (before cutoff) + TRACK button (active orders only)
//
// AddressComplete reliability:
// - Proxies AddressComplete JS/CSS through this backend.
//   GET /vendor/addresscomplete.js
//   GET /vendor/addresscomplete.css
//   GET /api/public/addresscomplete
//
// RESTORED:
// - Run windows/slots/minimums (Local: 6 OR $200; Owen: 6 AND $300; slots 12)
// - Admin quick action buttons (confirmed/shopping/packed/out_for_delivery/delivered/issue)
// - Per-run live tracking with admin start/stop + driver phone mode:
//    Admin start/stop: POST /api/admin/tracking/:runKey/start|stop
//    Driver ping:      POST /api/admin/tracking/:runKey/ping  { lat,lng,heading,speed,accuracy }
//    Customer view:    GET  /track/:runKey?token=...
//    Token-gated read: GET  /api/public/tracking/:runKey?token=...
// - Auto-start tracking when admin sets any order to "shopping" (you can change this trigger)

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");
const https = require("https");

const MongoStorePkg = require("connect-mongo");
const MongoStore = MongoStorePkg.default || MongoStorePkg;

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
const timezone = require("dayjs/plugin/timezone");
dayjs.extend(utc);
dayjs.extend(timezone);

const User = require("./models/User");

// =========================
// ENV / CONFIG
// =========================
const PORT = process.env.PORT || 10000;

const MONGODB_URI =
  process.env.MONGODB_URI ||
  process.env.MONGO_URI ||
  "mongodb://127.0.0.1:27017/tgr";

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const CANCEL_TOKEN_SECRET = process.env.CANCEL_TOKEN_SECRET || SESSION_SECRET;

// tracking token secret (separate is ideal)
const TRACKING_TOKEN_SECRET = process.env.TRACKING_TOKEN_SECRET || SESSION_SECRET;

const TZ = process.env.TZ || "America/Toronto";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const PUBLIC_SITE_URL =
  process.env.PUBLIC_SITE_URL || "https://tobermorygroceryrun.ca";

const MAPBOX_PUBLIC_TOKEN = process.env.MAPBOX_PUBLIC_TOKEN || "";

// Square links (override via Render env)
const SQUARE_PAY_GROCERIES_LINK =
  process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8";
const SQUARE_PAY_FEES_LINK =
  process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs";

const SQUARE_LINK_STANDARD =
  process.env.SQUARE_LINK_STANDARD || "https://square.link/u/iaziCZjG";
const SQUARE_LINK_ROUTE =
  process.env.SQUARE_LINK_ROUTE || "https://square.link/u/P5ROgqyp";
const SQUARE_LINK_ACCESS =
  process.env.SQUARE_LINK_ACCESS || "https://square.link/u/lHtHtvqG";
const SQUARE_LINK_ACCESSPRO =
  process.env.SQUARE_LINK_ACCESSPRO || "https://square.link/u/S0Y5Fysa";

const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:3000",
  "http://localhost:8888",
];

// Canada Post AddressComplete key (fallback)
const CANADAPOST_KEY = process.env.CANADAPOST_KEY || "mn86-az16-ku32-hj78";

// =========================
// APP + MIDDLEWARE
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

app.use(express.json({ limit: "6mb" }));
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
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

app.get("/favicon.ico", (_req, res) => res.status(204).end());

// Uploads
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 },
});

// =========================
// PASSPORT (GOOGLE OAUTH)
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
            (profile.emails && profile.emails[0] && profile.emails[0].value) ||
            "";
          const normalized = String(email).toLowerCase().trim();
          if (!normalized) return done(null, false);

          const update = {
            googleId: profile.id,
            email: normalized,
            name: profile.displayName || "",
            photo:
              (profile.photos &&
                profile.photos[0] &&
                profile.photos[0].value) ||
              "",
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
                profile: {
                  version: 1,
                  complete: false,
                  defaultId: "",
                  addresses: [],
                },
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
// PRICING BASELINE
// =========================
const PRICING = {
  serviceFee: 25,
  zone: { A: 20, B: 15, C: 10, D: 25 },
  owenRunFeePerOrder: 20,
  addOns: {
    extraStore: 8,
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
// MODELS (IN FILE)
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

const AllowedStates = [
  "submitted",
  "confirmed",
  "shopping",
  "packed",
  "out_for_delivery",
  "delivered",
  "issue",
  "cancelled",
];

const ACTIVE_STATES = new Set([
  "submitted",
  "confirmed",
  "shopping",
  "packed",
  "out_for_delivery",
]);

const OrderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true, index: true },
    runKey: { type: String, required: true },
    runType: { type: String, enum: ["local", "owen"], required: true },

    customer: { fullName: String, email: String, phone: String },

    address: {
      town: String,
      streetAddress: String,
      unit: { type: String, default: "" },
      postalCode: { type: String, default: "" },
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
      attachment: {
        originalName: String,
        mimeType: String,
        size: Number,
        path: String,
      },
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

    payments: {
      fees: {
        status: { type: String, default: "unpaid" },
        note: { type: String, default: "" },
        paidAt: { type: Date, default: null },
      },
      groceries: {
        status: { type: String, default: "unpaid" },
        note: { type: String, default: "" },
        paidAt: { type: Date, default: null },
      },
    },

    status: {
      state: { type: String, enum: AllowedStates, default: "submitted" },
      note: { type: String, default: "" },
      updatedAt: { type: Date, default: Date.now },
      updatedBy: { type: String, default: "system" },
    },

    statusHistory: {
      type: [
        {
          state: { type: String, enum: AllowedStates },
          note: String,
          at: Date,
          by: String,
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

// Per-run tracking session
const TrackingSchema = new mongoose.Schema(
  {
    runKey: { type: String, unique: true, index: true },

    enabled: { type: Boolean, default: false },
    startedAt: { type: Date, default: null },
    stoppedAt: { type: Date, default: null },

    // last point
    lastLat: { type: Number, default: null },
    lastLng: { type: Number, default: null },
    lastHeading: { type: Number, default: null },
    lastSpeed: { type: Number, default: null },
    lastAccuracy: { type: Number, default: null },
    lastAt: { type: Date, default: null },

    // who toggled
    updatedBy: { type: String, default: "system" },
  },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const Tracking = mongoose.model("Tracking", TrackingSchema);

// =========================
// HELPERS
// =========================
function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function csvEscape(val) {
  const s = String(val ?? "");
  if (s.includes('"') || s.includes(",") || s.includes("\n") || s.includes("\r")) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
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

// ===== Run scheduling (biweekly, DB-driven) =====
function runKeyToDayjs(runKey) {
  try {
    const dateStr = String(runKey || "").slice(0, 10); // YYYY-MM-DD
    const d = dayjs(dateStr).tz(TZ);
    return d.isValid() ? d : null;
  } catch {
    return null;
  }
}

function computeTimesForDelivery(deliveryDayjs, type) {
  const delivery = dayjs(deliveryDayjs).tz(TZ);
  if (type === "local") {
    const cutoff = delivery
      .subtract(2, "day")
      .hour(18)
      .minute(0)
      .second(0)
      .millisecond(0); // Thu 6pm
    const opens = delivery
      .subtract(5, "day")
      .hour(0)
      .minute(0)
      .second(0)
      .millisecond(0); // Mon 12am
    return { delivery, cutoff, opens };
  }
  // owen
  const cutoff = delivery
    .subtract(2, "day")
    .hour(18)
    .minute(0)
    .second(0)
    .millisecond(0); // Fri 6pm (delivery Sunday)
  const opens = delivery
    .subtract(6, "day")
    .hour(0)
    .minute(0)
    .second(0)
    .millisecond(0); // Mon 12am
  return { delivery, cutoff, opens };
}

// RESTORED minimums/slots text
function runMinimumConfig(type) {
  if (type === "local")
    return { minOrders: 6, minFees: 200, minLogic: "OR", minimumText: "Minimum: 6 orders OR $200 booked fees" };
  return { minOrders: 6, minFees: 300, minLogic: "AND", minimumText: "Minimum: 6 orders AND $300 booked fees" };
}

function meetsMinimums(run) {
  if (run.minLogic === "AND") return run.bookedOrdersCount >= run.minOrders && run.bookedFeesTotal >= run.minFees;
  return run.bookedOrdersCount >= run.minOrders || run.bookedFeesTotal >= run.minFees;
}

async function getOrCreateNextRun(type) {
  const now = nowTz();

  // If there is already a future run for this type, use it
  const existing = await Run.findOne({ type, cutoffAt: { $gt: now.toDate() } }).sort({ opensAt: 1 }).lean();
  if (existing) return existing;

  // Otherwise create the next run as (latest run of this type + 14 days)
  const latest = await Run.findOne({ type }).sort({ opensAt: -1 }).lean();

  let delivery;
  if (latest?.runKey) {
    const lastDelivery = runKeyToDayjs(latest.runKey);
    delivery = (lastDelivery || now).add(14, "day");
  } else {
    // Seed only (first time): next Saturday for local, next Sunday for owen
    delivery = type === "local" ? nextDow(6, now) : nextDow(0, now);
  }

  const { cutoff, opens } = computeTimesForDelivery(delivery, type);
  const runKey = delivery.format("YYYY-MM-DD") + "-" + type;
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

  return created.toObject();
}

async function ensureUpcomingRuns() {
  const out = {};
  for (const type of ["local", "owen"]) {
    let run = await getOrCreateNextRun(type);

    // recalc booked counts/fees based on ACTIVE orders
    const needsRecalc =
      !run.lastRecalcAt ||
      dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(60, "second").toDate());

    if (needsRecalc) {
      const agg = await Order.aggregate([
        { $match: { runKey: run.runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } } },
        { $group: { _id: "$runKey", c: { $sum: 1 }, fees: { $sum: "$pricingSnapshot.totalFees" } } },
      ]);
      const c = agg?.[0]?.c || 0;
      const fees = agg?.[0]?.fees || 0;

      await Run.updateOne(
        { runKey: run.runKey },
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
  return "TGR-" + String(c.seq).padStart(5, "0");
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
    ? input.extraStores.map(String).map((s) => s.trim()).filter(Boolean)
    : safeJsonArray(input.extraStoresJson);

  const pages = Math.max(0, Number(input.printPages || 0));
  const grocerySubtotal = Math.max(0, Number(input.grocerySubtotal || 0));

  const memberTier = String(input.memberTier || "");
  const applyPerk = String(input.applyPerk || "yes") === "yes";
  const disc = membershipDiscounts(memberTier, applyPerk);

  const serviceFee = PRICING.serviceFee;
  const zoneFee = PRICING.zone[zone] || 0;
  const runFee = runType === "owen" ? PRICING.owenRunFeePerOrder : 0;

  let addOnsFees = 0;
  if (extraStores.length) addOnsFees += extraStores.length * PRICING.addOns.extraStore;
  if (String(input.addon_printing || "") === "yes" && pages > 0) addOnsFees += calcPrinting(pages);

  let surcharges = 0;
  if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) {
    surcharges += PRICING.groceryUnderMin.surcharge;
  }

  const serviceOff = Math.min(serviceFee, disc.serviceOff || 0);
  const optionA = Math.min(zoneFee, disc.zoneOff || 0);
  const optionB = Math.min(addOnsFees + runFee, disc.freeAddonUpTo || 0);
  const bestOr = Math.max(optionA, optionB);
  const discount = serviceOff + bestOr;

  const totalFees = Math.max(
    0,
    serviceFee + zoneFee + runFee + addOnsFees + surcharges - discount
  );
  return { totals: { serviceFee, zoneFee, runFee, addOnsFees, surcharges, discount, totalFees } };
}

function yn(v) {
  return v === true || String(v || "").toLowerCase() === "yes";
}

function isProfileComplete(profile) {
  const p = profile || {};
  if (p.complete === true) return true;

  const fullName = String(p.fullName || "").trim();
  const phone = String(p.phone || "").trim();
  const contactPref = String(p.contactPref || "").trim();
  const contactAuth = p.contactAuth === true;

  const addresses = Array.isArray(p.addresses) ? p.addresses : [];
  const hasAddress = addresses.some((a) => {
    const street = String(a.streetAddress || "").trim();
    const town = String(a.town || "").trim();
    const zone = String(a.zone || "").trim();
    const postalCode = String(a.postalCode || "").trim();
    return !!street && !!town && !!zone && !!postalCode;
  });

  const consentsOk = p.consentTerms === true && p.consentPrivacy === true;

  return !!fullName && !!phone && !!contactPref && contactAuth && hasAddress && consentsOk;
}

function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "Sign-in required." });
  next();
}

function requireProfileComplete(req, res, next) {
  if (!isProfileComplete(req.user?.profile || {})) {
    return res.status(403).json({ ok: false, error: "Account setup required. Please complete your profile." });
  }
  next();
}

function isAdminEmail(email) {
  const e = String(email || "").toLowerCase().trim();
  if (!e) return false;
  if (!ADMIN_EMAILS.length) return true;
  return ADMIN_EMAILS.includes(e);
}

function requireAdmin(req, res, next) {
  const email = String(req.user?.email || "").toLowerCase().trim();
  if (!email || !isAdminEmail(email)) return res.status(403).send("Admin access required.");
  next();
}

// ===== Cancel token helpers =====
function base64urlEncode(buf) {
  return Buffer.from(buf).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function base64urlDecodeToString(b64url) {
  const pad = b64url.length % 4 ? "=".repeat(4 - (b64url.length % 4)) : "";
  const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}
function signCancelToken(orderId, expMs) {
  const payload = `${orderId}.${String(expMs)}`;
  const sig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payload).digest();
  return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`;
}
function verifyCancelToken(orderId, token) {
  try {
    const parts = String(token || "").trim().split(".");
    if (parts.length !== 2) return { ok: false };
    const payloadStr = base64urlDecodeToString(parts[0]);
    const sigB64 = parts[1];
    const [oid, expStr] = payloadStr.split(".");
    const expMs = Number(expStr);
    if (oid !== orderId || !Number.isFinite(expMs)) return { ok: false };

    const expectedSig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payloadStr).digest();
    const expectedB64 = base64urlEncode(expectedSig);

    const a = Buffer.from(sigB64);
    const b = Buffer.from(expectedB64);
    if (a.length !== b.length) return { ok: false };
    if (!crypto.timingSafeEqual(a, b)) return { ok: false };
    return { ok: true, expMs };
  } catch {
    return { ok: false };
  }
}

// ===== Tracking token helpers (orderId + runKey) =====
function signTrackingToken(orderId, runKey, expMs) {
  const payload = `${orderId}.${runKey}.${String(expMs)}`;
  const sig = crypto.createHmac("sha256", TRACKING_TOKEN_SECRET).update(payload).digest();
  return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`;
}
function verifyTrackingToken(token) {
  try {
    const parts = String(token || "").trim().split(".");
    if (parts.length !== 2) return { ok: false };
    const payloadStr = base64urlDecodeToString(parts[0]);
    const sigB64 = parts[1];

    const segs = payloadStr.split(".");
    if (segs.length < 3) return { ok: false };
    const orderId = segs[0];
    const expStr = segs[segs.length - 1];
    const runKey = segs.slice(1, -1).join("."); // preserve hyphens etc

    const expMs = Number(expStr);
    if (!orderId || !runKey || !Number.isFinite(expMs)) return { ok: false };

    const expectedSig = crypto.createHmac("sha256", TRACKING_TOKEN_SECRET).update(payloadStr).digest();
    const expectedB64 = base64urlEncode(expectedSig);

    const a = Buffer.from(sigB64);
    const b = Buffer.from(expectedB64);
    if (a.length !== b.length) return { ok: false };
    if (!crypto.timingSafeEqual(a, b)) return { ok: false };

    if (Date.now() > expMs) return { ok: false, error: "expired" };

    return { ok: true, orderId, runKey, expMs };
  } catch {
    return { ok: false };
  }
}

// =========================
// AddressComplete proxy (server-side)
// =========================
function proxyRemote(url, res, contentType) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Content-Type", contentType);

  https
    .get(url, (r) => {
      if (r.statusCode && r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
        return proxyRemote(r.headers.location, res, contentType);
      }
      if (r.statusCode !== 200) {
        res.statusCode = 502;
        let body = "";
        r.on("data", (c) => (body += c.toString("utf8")));
        r.on("end", () => {
          res.end(`Upstream error (${r.statusCode}): ${body.slice(0, 400)}`);
        });
        return;
      }
      r.pipe(res);
    })
    .on("error", (e) => {
      res.statusCode = 502;
      res.end("Proxy error: " + String(e));
    });
}

app.get("/vendor/addresscomplete.css", (_req, res) => {
  const url = `https://ws1.postescanada-canadapost.ca/css/addresscomplete-2.50.min.css?key=${encodeURIComponent(CANADAPOST_KEY)}`;
  proxyRemote(url, res, "text/css; charset=utf-8");
});

app.get("/vendor/addresscomplete.js", (_req, res) => {
  const url = `https://ws1.postescanada-canadapost.ca/js/addresscomplete-2.50.min.js?key=${encodeURIComponent(CANADAPOST_KEY)}`;
  proxyRemote(url, res, "application/javascript; charset=utf-8");
});

app.get("/api/public/addresscomplete", (_req, res) => {
  res.json({
    ok: true,
    css: `https://api.tobermorygroceryrun.ca/vendor/addresscomplete.css`,
    js: `https://api.tobermorygroceryrun.ca/vendor/addresscomplete.js`,
    note: "Use these URLs in index.html <head> instead of ws1.postescanada-canadapost.ca for more reliable execution.",
  });
});

// =========================
// PUBLIC CONFIG
// =========================
app.get("/api/public/config", (_req, res) => {
  res.json({ ok: true, mapboxPublicToken: MAPBOX_PUBLIC_TOKEN || "" });
});

// =========================
// AUTH ROUTES
// =========================
app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
    return res.status(500).send("Google auth is not configured on this server.");
  }
  req.session.returnTo = String(req.query.returnTo || (PUBLIC_SITE_URL + "/")).trim();
  return passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: PUBLIC_SITE_URL + "/?login=failed" }),
  async (req, res) => {
    const rt = req.session.returnTo || (PUBLIC_SITE_URL + "/");
    delete req.session.returnTo;
    try {
      const u = await User.findById(req.user._id).lean();
      if (!isProfileComplete(u?.profile || {})) {
        return res.redirect(PUBLIC_SITE_URL + "/?tab=account&onboarding=1");
      }
    } catch {}
    res.redirect(rt);
  }
);

app.get("/logout", (req, res) => {
  const returnTo = String(req.query.returnTo || (PUBLIC_SITE_URL + "/")).trim();
  req.session.destroy(() => res.redirect(returnTo));
});

// =========================
// API: ME + PROFILE
// =========================
app.get("/api/me", (req, res) => {
  const u = req.user;
  res.json({
    ok: true,
    loggedIn: !!u,
    email: u?.email || null,
    name: u?.name || "",
    photo: u?.photo || "",
    membershipLevel: u?.membershipLevel || "none",
    membershipStatus: u?.membershipStatus || "inactive",
    renewalDate: u?.renewalDate || null,
    profileComplete: isProfileComplete(u?.profile || {}),
    isAdmin: !!u?.email && isAdminEmail(u.email),
  });
});

app.get("/api/profile", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  res.json({
    ok: true,
    profile: u?.profile || {},
    profileComplete: isProfileComplete(u?.profile || {}),
    email: u?.email || "",
    name: u?.name || "",
    photo: u?.photo || "",
  });
});

app.post("/api/profile", requireLogin, async (req, res) => {
  try {
    const b = req.body || {};
    const u = await User.findById(req.user._id);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    const addresses = Array.isArray(b.addresses) ? b.addresses : [];

    const newProfile = {
      version: 1,
      fullName: String(b.fullName || "").trim(),
      preferredName: String(b.preferredName || "").trim(),
      phone: String(b.phone || "").trim(),
      altPhone: String(b.altPhone || "").trim(),
      contactPref: String(b.contactPref || "").trim(),
      contactAuth: yn(b.contactAuth),

      subsDefault: String(b.subsDefault || "").trim(),
      dropoffDefault: String(b.dropoffDefault || "").trim(),

      customerType: String(b.customerType || "").trim(),
      accessibility: String(b.accessibility || "").trim(),
      dietary: String(b.dietary || "").trim(),
      notes: String(b.notes || "").trim(),

      addresses: addresses.map((a) => ({
        id: String(a.id || "").trim() || String(Math.random()).slice(2),
        label: String(a.label || "").trim(),
        town: String(a.town || "").trim(),
        zone: String(a.zone || "").trim(),
        streetAddress: String(a.streetAddress || "").trim(),
        unit: String(a.unit || "").trim(),
        postalCode: String(a.postalCode || "").trim(),
        instructions: String(a.instructions || "").trim(),
        gateCode: String(a.gateCode || "").trim(),
      })),

      defaultId: String(b.defaultId || "").trim(),

      consentTerms: yn(b.consentTerms),
      consentPrivacy: yn(b.consentPrivacy),
      consentMarketing: yn(b.consentMarketing),
    };

    if (!newProfile.defaultId && newProfile.addresses.length) newProfile.defaultId = newProfile.addresses[0].id;

    newProfile.complete = isProfileComplete(newProfile);
    newProfile.completedAt = newProfile.complete ? new Date().toISOString() : null;

    u.profile = newProfile;
    u.markModified("profile");
    await u.save();

    res.json({ ok: true, profileComplete: newProfile.complete === true, profile: newProfile });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// RUNS + ESTIMATOR
// =========================
app.get("/api/runs/active", async (_req, res) => {
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

app.post("/api/estimator", (req, res) => {
  try {
    const breakdown = computeFeeBreakdown(req.body || {});
    res.json({ ok: true, breakdown });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// ORDERS
// =========================
function pickDefaultAddress(profile) {
  const p = profile || {};
  const arr = Array.isArray(p.addresses) ? p.addresses : [];
  if (!arr.length) return null;
  const defId = String(p.defaultId || "").trim();
  const found = defId ? arr.find((a) => String(a.id) === defId) : null;
  return found || arr[0] || null;
}

app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};
    const user = await User.findById(req.user._id).lean();
    const profile = user?.profile || {};

    if (!yn(b.consent_terms) || !yn(b.consent_accuracy) || !yn(b.consent_dropoff)) {
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    const runs = await ensureUpcomingRuns();
    const runType = String(b.runType || "");
    const run = runs[runType];
    if (!run) return res.status(400).json({ ok: false, error: "Invalid runType." });

    const now = nowTz();
    const opensAt = dayjs(run.opensAt).tz(TZ);
    const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    if (!(now.isAfter(opensAt) && now.isBefore(cutoffAt))) {
      return res.status(403).json({ ok: false, error: "Ordering is closed for this run." });
    }

    const defAddr = pickDefaultAddress(profile);

    const fullName = String(b.fullName || profile.fullName || user.name || "").trim();
    const phone = String(b.phone || profile.phone || "").trim();

    const town = String(b.town || defAddr?.town || "").trim();
    const streetAddress = String(b.streetAddress || defAddr?.streetAddress || "").trim();
    const unit = String(b.unit || defAddr?.unit || "").trim();
    const postalCode = String(b.postalCode || defAddr?.postalCode || "").trim();
    const zone = String(b.zone || defAddr?.zone || "").trim();

    const primaryStore = String(b.primaryStore || "").trim();
    const groceryList = String(b.groceryList || "").trim();

    const dropoffPref = String(b.dropoffPref || profile.dropoffDefault || "").trim();
    const subsPref = String(b.subsPref || profile.subsDefault || "").trim();
    const contactPref = String(b.contactPref || profile.contactPref || "").trim();

    const required = [
      ["fullName", fullName],
      ["phone", phone],
      ["town", town],
      ["streetAddress", streetAddress],
      ["postalCode", postalCode],
      ["zone", zone],
      ["runType", runType],
      ["primaryStore", primaryStore],
      ["groceryList", groceryList],
      ["dropoffPref", dropoffPref],
      ["subsPref", subsPref],
      ["contactPref", contactPref],
    ];
    for (const [k, v] of required) {
      if (!String(v || "").trim()) return res.status(400).json({ ok: false, error: "Missing required field: " + k });
    }

    const orderId = await nextOrderId();
    const extraStores = safeJsonArray(b.extraStores);

    let attachment = null;
    if (req.file) {
      attachment = {
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: req.file.path,
      };
    }

    const pricingSnapshot = computeFeeBreakdown({
      zone,
      runType,
      extraStores,
      grocerySubtotal: Number(b.grocerySubtotal || 0),
      addon_printing: b.addon_printing || "no",
      printPages: Number(b.printPages || 0),
      memberTier: b.memberTier || "",
      applyPerk: b.applyPerk || "yes",
    }).totals;

    // Slot enforcement based on Run.bookedOrdersCount
    const maxSlots = run.maxSlots || 12;
    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedOrdersCount: { $lt: maxSlots } },
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees }, $set: { lastRecalcAt: new Date() } },
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    await Order.create({
      orderId,
      runKey: run.runKey,
      runType,
      customer: { fullName, email: String(user.email || "").trim().toLowerCase(), phone },
      address: { town, streetAddress, unit, postalCode, zone },
      stores: { primary: primaryStore, extra: extraStores },
      preferences: { dropoffPref, subsPref, contactPref, contactAuth: true },
      list: { groceryListText: groceryList, attachment },
      consents: { terms: true, accuracy: true, dropoff: true },
      pricingSnapshot,
      payments: { fees: { status: "unpaid" }, groceries: { status: "unpaid" } },
      status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" },
      statusHistory: [{ state: "submitted", note: "", at: new Date(), by: "customer" }],
    });

    const cancelUntilMs = cutoffAt.toDate().getTime();
    const cancelToken = signCancelToken(orderId, cancelUntilMs);
    const cancelUntilLocal = fmtLocal(cutoffAt.toDate());

    res.json({ ok: true, orderId, runKey: run.runKey, cancelToken, cancelUntilLocal });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/orders/:orderId/cancel", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const token = String(req.body?.token || "").trim();

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const run = await Run.findOne({ runKey: order.runKey }).lean();
    if (!run?.cutoffAt) return res.status(500).json({ ok: false, error: "Run cutoff not available" });

    const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    const now = nowTz();

    const isActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    if (!isActive) return res.status(400).json({ ok: false, error: "Order cannot be cancelled in its current status." });

    const v = verifyCancelToken(orderId, token);
    if (!v.ok) return res.status(403).json({ ok: false, error: "Invalid cancel token." });

    if (!now.isBefore(cutoffAt)) {
      return res.status(403).json({ ok: false, error: "Cancellation window closed (past cutoff). After-cutoff policy applies." });
    }

    const fees = Number(order.pricingSnapshot?.totalFees || 0);
    await Run.updateOne(
      { runKey: order.runKey },
      { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }
    );

    order.status.state = "cancelled";
    order.status.note = "Cancelled by customer";
    order.status.updatedAt = new Date();
    order.status.updatedBy = "customer";
    order.statusHistory.push({ state: "cancelled", note: "Cancelled by customer", at: new Date(), by: "customer" });

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// TRACKING (per run)
// =========================
async function ensureTrackingDoc(runKey) {
  const t = await Tracking.findOneAndUpdate(
    { runKey },
    { $setOnInsert: { runKey, enabled: false, startedAt: null, stoppedAt: null, updatedBy: "system" } },
    { upsert: true, new: true }
  ).lean();
  return t;
}

// Token-gated read: only ACTIVE orders can track (validated by orderId in token)
app.get("/api/public/tracking/:runKey", async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const token = String(req.query.token || "").trim();

    const vt = verifyTrackingToken(token);
    if (!vt.ok) return res.status(403).json({ ok: false, error: "Invalid tracking token." });
    if (vt.runKey !== runKey) return res.status(403).json({ ok: false, error: "Token/run mismatch." });

    const order = await Order.findOne({ orderId: vt.orderId, runKey }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found." });

    const state = order?.status?.state || "submitted";
    if (!ACTIVE_STATES.has(state)) {
      return res.status(403).json({ ok: false, error: "Tracking is only available for active orders." });
    }

    const t = await ensureTrackingDoc(runKey);
    if (!t.enabled || !t.lastAt || typeof t.lastLat !== "number" || typeof t.lastLng !== "number") {
      return res.json({ ok: true, enabled: !!t.enabled, hasFix: false });
    }

    res.json({
      ok: true,
      enabled: true,
      hasFix: true,
      last: {
        lat: t.lastLat,
        lng: t.lastLng,
        heading: t.lastHeading,
        speed: t.lastSpeed,
        accuracy: t.lastAccuracy,
        at: t.lastAt,
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Public tracking page (token required)
app.get("/track/:runKey", async (req, res) => {
  const runKey = String(req.params.runKey || "").trim();
  const token = String(req.query.token || "").trim();

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>TGR Live Tracking</title>
<style>
  :root{
    --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.75);
    --red:#e3342f; --red2:#ff4a44;
    --radius:14px;
  }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1100px;margin:0 auto;padding:14px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .muted{color:var(--muted);}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;}
  #map{height:64vh;min-height:380px;border-radius:14px;border:1px solid rgba(255,255,255,.14);overflow:hidden;background:rgba(0,0,0,.25);}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
</style>
<link href="https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.css" rel="stylesheet">
<script src="https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.js"></script>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row">
      <div>
        <div style="font-weight:1000;font-size:22px;">Live Tracking</div>
        <div class="muted">Run: <span class="pill">${escapeHtml(runKey)}</span></div>
      </div>
      <div class="muted" id="status">Loading…</div>
    </div>
    <div style="margin-top:12px;" id="map"></div>
    <div class="muted" style="margin-top:10px;" id="lastLine"></div>
  </div>
</div>

<script>
  const RUNKEY = ${JSON.stringify(runKey)};
  const TOKEN = ${JSON.stringify(token)};
  const API = ${JSON.stringify("https://api.tobermorygroceryrun.ca")} + "/api/public/tracking/" + encodeURIComponent(RUNKEY) + "?token=" + encodeURIComponent(TOKEN);

  async function getToken(){
    try{
      const r = await fetch(${JSON.stringify("https://api.tobermorygroceryrun.ca")} + "/api/public/config");
      const d = await r.json().catch(()=>({}));
      return d.mapboxPublicToken || "";
    } catch { return ""; }
  }

  let map, marker;
  let inited = false;

  function setStatus(txt){ document.getElementById("status").textContent = txt; }
  function setLast(txt){ document.getElementById("lastLine").textContent = txt; }

  async function initMap(){
    const token = await getToken();
    if(!token){
      setStatus("Map token missing");
      return;
    }
    mapboxgl.accessToken = token;
    map = new mapboxgl.Map({
      container: "map",
      style: "mapbox://styles/mapbox/streets-v12",
      center: [-81.66, 45.25],
      zoom: 9
    });
    marker = new mapboxgl.Marker().setLngLat([-81.66, 45.25]).addTo(map);
    inited = true;
  }

  async function poll(){
    try{
      const r = await fetch(API, { cache:"no-store" });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false){
        setStatus(d.error || "Tracking unavailable");
        return;
      }
      if(!d.enabled){
        setStatus("Tracking is OFF");
        setLast("");
        return;
      }
      if(!d.hasFix){
        setStatus("Tracking ON (waiting for GPS fix…) ");
        setLast("");
        return;
      }
      const lat = d.last.lat, lng = d.last.lng;
      const at = d.last.at ? new Date(d.last.at).toLocaleString() : "";
      setStatus("Tracking ON");
      setLast(at ? ("Last update: " + at) : "");

      if(inited){
        marker.setLngLat([lng, lat]);
        map.setCenter([lng, lat]);
      }
    } catch(e){
      setStatus("Network error");
    }
  }

  (async ()=>{
    await initMap();
    await poll();
    setInterval(poll, 4000);
  })();
</script>
</body>
</html>`);
});

// =========================
// ADMIN: Tracking control + driver ping
// =========================
app.post("/api/admin/tracking/:runKey/start", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    const t = await Tracking.findOneAndUpdate(
      { runKey },
      { $set: { enabled: true, startedAt: new Date(), stoppedAt: null, updatedBy: by } },
      { upsert: true, new: true }
    ).lean();

    res.json({ ok: true, tracking: { runKey: t.runKey, enabled: t.enabled } });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/tracking/:runKey/stop", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    const t = await Tracking.findOneAndUpdate(
      { runKey },
      { $set: { enabled: false, stoppedAt: new Date(), updatedBy: by } },
      { upsert: true, new: true }
    ).lean();

    res.json({ ok: true, tracking: { runKey: t.runKey, enabled: t.enabled } });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/tracking/:runKey/ping", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    const lat = Number(req.body?.lat);
    const lng = Number(req.body?.lng);
    const heading = req.body?.heading === null || req.body?.heading === undefined ? null : Number(req.body?.heading);
    const speed = req.body?.speed === null || req.body?.speed === undefined ? null : Number(req.body?.speed);
    const accuracy = req.body?.accuracy === null || req.body?.accuracy === undefined ? null : Number(req.body?.accuracy);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ ok: false, error: "lat/lng required" });
    }

    const t = await Tracking.findOne({ runKey }).lean();
    if (!t?.enabled) {
      return res.status(403).json({ ok: false, error: "Tracking is OFF for this run." });
    }

    await Tracking.updateOne(
      { runKey },
      {
        $set: {
          lastLat: lat,
          lastLng: lng,
          lastHeading: Number.isFinite(heading) ? heading : null,
          lastSpeed: Number.isFinite(speed) ? speed : null,
          lastAccuracy: Number.isFinite(accuracy) ? accuracy : null,
          lastAt: new Date(),
          updatedBy: by,
        },
      }
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// A simple driver phone page: geolocation watch -> pings backend for selected runKey (admin only)
app.get("/driver", requireLogin, requireAdmin, async (req, res) => {
  const runKey = String(req.query.runKey || "").trim();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Driver Mode</title>
<style>
  :root{--bg:#0b0b0b;--panel:rgba(255,255,255,.06);--line:rgba(255,255,255,.14);--text:#fff;--muted:rgba(255,255,255,.75);--red:#e3342f;--red2:#ff4a44;--radius:14px;}
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:900px;margin:0 auto;padding:14px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;}
  .btn{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-weight:900;border-radius:999px;padding:10px 14px;cursor:pointer;}
  .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);}
  .muted{color:var(--muted);}
  input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.25);color:#fff;}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row">
      <div>
        <div style="font-weight:1000;font-size:22px;">Driver Mode</div>
        <div class="muted">This sends your phone GPS to TGR while tracking is ON.</div>
      </div>
      <a class="btn" href="/admin">Back</a>
    </div>

    <div style="margin-top:12px;">
      <div class="muted">Run Key</div>
      <input id="rk" value="${escapeHtml(runKey)}" placeholder="YYYY-MM-DD-local or YYYY-MM-DD-owen">
    </div>

    <div class="row" style="margin-top:12px;">
      <button class="btn primary" id="start">Start sending</button>
      <button class="btn" id="stop">Stop</button>
      <div class="muted" id="status">Idle</div>
    </div>

    <div class="muted" style="margin-top:10px;" id="last"></div>
  </div>
</div>

<script>
  let watchId = null;

  function setStatus(t){ document.getElementById("status").textContent = t; }
  function setLast(t){ document.getElementById("last").textContent = t; }

  async function ping(runKey, pos){
    const c = pos.coords || {};
    const body = {
      lat: c.latitude,
      lng: c.longitude,
      heading: (c.heading === null ? null : c.heading),
      speed: (c.speed === null ? null : c.speed),
      accuracy: (c.accuracy === null ? null : c.accuracy),
    };

    const r = await fetch("/api/admin/tracking/" + encodeURIComponent(runKey) + "/ping", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify(body),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Ping failed");
  }

  document.getElementById("start").addEventListener("click", ()=>{
    const runKey = document.getElementById("rk").value.trim();
    if(!runKey) return setStatus("Enter a runKey");

    if(!navigator.geolocation) return setStatus("Geolocation not supported");

    setStatus("Starting…");
    watchId = navigator.geolocation.watchPosition(async (pos)=>{
      try{
        await ping(runKey, pos);
        setStatus("Sending ✅");
        setLast("Last: " + new Date().toLocaleTimeString());
      } catch(e){
        setStatus("Error: " + e.message);
      }
    }, (err)=>{
      setStatus("GPS error: " + (err && err.message ? err.message : "unknown"));
    }, { enableHighAccuracy:true, maximumAge:1000, timeout:8000 });
  });

  document.getElementById("stop").addEventListener("click", ()=>{
    if(watchId !== null){
      navigator.geolocation.clearWatch(watchId);
      watchId = null;
    }
    setStatus("Stopped");
  });
</script>
</body>
</html>`);
});

// =========================
// MEMBER PORTAL (RESTORED + TRACK)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const name = String(req.user?.name || "").trim();

    const orders = await Order.find({ "customer.email": email })
      .sort({ createdAt: -1 })
      .limit(40)
      .lean();

    const runKeys = Array.from(new Set(orders.map((o) => o.runKey).filter(Boolean)));
    const runs = await Run.find({ runKey: { $in: runKeys } }).lean();
    const runByKey = new Map(runs.map((r) => [r.runKey, r]));

    const trackDocs = await Tracking.find({ runKey: { $in: runKeys } }).lean();
    const trackByRunKey = new Map(trackDocs.map((t) => [t.runKey, t]));

    const now = nowTz();

    const rows = orders.map((o) => {
      const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
      const status = o.status?.state || "submitted";
      const run = runByKey.get(o.runKey);
      const cutoffAt = run?.cutoffAt ? dayjs(run.cutoffAt).tz(TZ) : null;
      const cancelOpen = cutoffAt ? now.isBefore(cutoffAt) : false;

      // Cancel button (active + before cutoff)
      let cancelHtml = `<span class="muted">Not available</span>`;
      if (ACTIVE_STATES.has(status) && cancelOpen) {
        const token = signCancelToken(o.orderId, cutoffAt.toDate().getTime());
        cancelHtml = `<button class="btn" data-cancel="${escapeHtml(o.orderId)}" data-token="${escapeHtml(token)}">Cancel</button>`;
      } else if (status === "cancelled") {
        cancelHtml = `<span class="pill">Cancelled</span>`;
      } else if (!cancelOpen && ACTIVE_STATES.has(status)) {
        cancelHtml = `<span class="muted">Past cutoff</span>`;
      }

      // Track button (ACTIVE orders only, and only if tracking enabled for that run)
      let trackHtml = `<span class="muted">—</span>`;
      const t = trackByRunKey.get(o.runKey);
      if (ACTIVE_STATES.has(status) && t?.enabled) {
        // Token valid for 7 days from now (covers the run day + delivery window)
        const expMs = Date.now() + 7 * 24 * 60 * 60 * 1000;
        const tt = signTrackingToken(o.orderId, o.runKey, expMs);
        const url = `/track/${encodeURIComponent(o.runKey)}?token=${encodeURIComponent(tt)}`;
        trackHtml = `<a class="btn primary" href="${url}" target="_blank" rel="noopener">Track</a>`;
      } else if (ACTIVE_STATES.has(status) && !t?.enabled) {
        trackHtml = `<span class="muted">Tracking off</span>`;
      } else if (!ACTIVE_STATES.has(status)) {
        trackHtml = `<span class="muted">Inactive</span>`;
      }

      return `
        <tr>
          <td><div style="font-weight:1000;">${escapeHtml(o.orderId)}</div><div class="muted" style="font-size:12px;">${escapeHtml(fmtLocal(o.createdAt))}</div></td>
          <td><div style="font-weight:900;">${escapeHtml(o.address?.town || "")} (Zone ${escapeHtml(o.address?.zone || "")})</div>
              <div class="muted" style="font-size:12px;">${escapeHtml(o.address?.streetAddress || "")} • ${escapeHtml(o.address?.postalCode || "")}</div></td>
          <td><span class="pill">${escapeHtml(o.runType || "")}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.runKey || "")}</div></td>
          <td><span class="pill">${escapeHtml(status)}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.status?.note || "")}</div></td>
          <td>$${escapeHtml(fees)}</td>
          <td>${trackHtml}</td>
          <td>${cancelHtml}</td>
        </tr>
      `;
    }).join("");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Member Portal</title>
<style>
  :root{
    --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.75);
    --red:#e3342f; --red2:#ff4a44;
    --radius:14px;
  }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1100px;margin:0 auto;padding:16px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .btn{
    border:1px solid rgba(255,255,255,.18);
    background:rgba(255,255,255,.06);
    color:#fff;font-weight:900;
    border-radius:999px;
    padding:10px 14px;
    cursor:pointer;
    text-decoration:none;
    white-space:nowrap;
  }
  .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);}
  .btn.ghost{background:transparent;}
  .muted{color:var(--muted);}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;}
  th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;}
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
  .toast.show{display:block;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div>
        <div style="font-weight:1000;font-size:22px;">Member Portal</div>
        <div class="muted">Signed in as <strong>${escapeHtml(email)}</strong>${name ? ` • ${escapeHtml(name)}` : ""}</div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn" href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}" target="_blank" rel="noopener">Pay Grocery Total</a>
        <a class="btn" href="${escapeHtml(SQUARE_PAY_FEES_LINK)}" target="_blank" rel="noopener">Pay Service & Delivery Fees</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>

    <div class="hr"></div>

    <div style="overflow:auto;">
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Address</th>
            <th>Run</th>
            <th>Status</th>
            <th>Fees</th>
            <th>Tracking</th>
            <th>Cancel</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="7" class="muted">No orders yet.</td></tr>`}
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
  const toast = (msg)=>{
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(()=>el.classList.remove("show"), 3500);
  };

  async function cancelOrder(orderId, token){
    const ok = confirm("Cancel " + orderId + " before cutoff?");
    if(!ok) return;

    const r = await fetch("/api/orders/" + encodeURIComponent(orderId) + "/cancel", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ token }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Cancel failed");
    toast("Cancelled " + orderId);
    setTimeout(()=>location.reload(), 700);
  }

  document.querySelectorAll("[data-cancel]").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      cancelOrder(btn.getAttribute("data-cancel"), btn.getAttribute("data-token"));
    });
  });
</script>

</body>
</html>`);
  } catch (e) {
    res.status(500).send("Member portal error: " + String(e));
  }
});

// =========================
// ADMIN API ENDPOINTS
// =========================
app.get("/api/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(250, Math.max(1, Number(req.query.limit || 80)));
    const q = String(req.query.q || "").trim();
    const state = String(req.query.state || "").trim();
    const runKey = String(req.query.runKey || "").trim();

    const filter = {};
    if (runKey) filter.runKey = runKey;
    if (state) filter["status.state"] = state;

    if (q) {
      const safe = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(safe, "i");
      filter.$or = [
        { orderId: re },
        { "customer.fullName": re },
        { "customer.email": re },
        { "customer.phone": re },
        { "address.town": re },
        { "address.streetAddress": re },
        { "address.postalCode": re },
      ];
    }

    const items = await Order.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// RESTORED: quick status update endpoint
// Auto-start tracking when state becomes "shopping"
app.post("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const nextState = String(req.body?.state || "").trim();
    const note = String(req.body?.note || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    if (!AllowedStates.includes(nextState)) {
      return res.status(400).json({ ok: false, error: "Invalid state" });
    }

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    const willBeActive = ACTIVE_STATES.has(nextState);

    // Keep run counters consistent if moving in/out of active set
    if (wasActive && !willBeActive) {
      const fees = Number(order.pricingSnapshot?.totalFees || 0);
      await Run.updateOne(
        { runKey: order.runKey },
        { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }
      );
    } else if (!wasActive && willBeActive) {
      const fees = Number(order.pricingSnapshot?.totalFees || 0);
      await Run.updateOne(
        { runKey: order.runKey },
        { $inc: { bookedOrdersCount: 1, bookedFeesTotal: fees }, $set: { lastRecalcAt: new Date() } }
      );
    }

    order.status.state = nextState;
    order.status.note = note;
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state: nextState, note, at: new Date(), by });

    await order.save();

    // AUTO-START tracking when you mark any order as "shopping"
    if (nextState === "shopping") {
      await Tracking.findOneAndUpdate(
        { runKey: order.runKey },
        { $set: { enabled: true, startedAt: new Date(), stoppedAt: null, updatedBy: by } },
        { upsert: true }
      );
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/cancel", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const reason = String(req.body?.reason || "").trim() || "Cancelled by admin";
    const by = String(req.user?.email || "admin").toLowerCase();

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    if (wasActive) {
      const fees = Number(order.pricingSnapshot?.totalFees || 0);
      await Run.updateOne(
        { runKey: order.runKey },
        { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }
      );
    }

    order.status.state = "cancelled";
    order.status.note = reason;
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state: "cancelled", note: reason, at: new Date(), by });

    await order.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.delete("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    if (wasActive) {
      const fees = Number(order.pricingSnapshot?.totalFees || 0);
      await Run.updateOne(
        { runKey: order.runKey },
        { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }
      );
    }

    await Order.deleteOne({ orderId });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/admin/routific/export-csv", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.query.runKey || "").trim();
    if (!runKey) return res.status(400).send("Missing runKey");

    const orders = await Order.find({
      runKey,
      "status.state": { $in: Array.from(ACTIVE_STATES) },
    }).sort({ createdAt: 1 }).lean();

    const header = ["order_id","name","address","phone","email","notes","duration_seconds"];
    const rows = orders.map(o => {
      const name = o.customer?.fullName || "";
      const phone = o.customer?.phone || "";
      const email = o.customer?.email || "";
      const address =
        `${o.address?.streetAddress || ""}${o.address?.unit ? (" " + o.address.unit) : ""}, ` +
        `${o.address?.town || ""}, ON, ${o.address?.postalCode || ""}, Canada`
          .replace(/\s+/g, " ")
          .trim();

      const notes = [
        `TGR ${o.orderId}`,
        `Zone ${o.address?.zone || ""}`,
        o.preferences?.dropoffPref ? `Drop-off: ${o.preferences.dropoffPref}` : "",
        o.preferences?.subsPref ? `Subs: ${o.preferences.subsPref}` : "",
        o.stores?.primary ? `Store: ${o.stores.primary}` : "",
        (o.stores?.extra || []).length ? `Extra: ${(o.stores.extra || []).join(", ")}` : "",
      ].filter(Boolean).join(" | ");

      const duration = 360;
      return [o.orderId, name, address, phone, email, notes, String(duration)].map(csvEscape).join(",");
    });

    const csv = header.join(",") + "\n" + rows.join("\n") + "\n";
    const filename = `routific_${runKey}_deliveries.csv`;

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// =========================
// FULL ADMIN PAGE (RESTORED quick actions + tracking controls)
// =========================
app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  const email = String(req.user?.email || "").toLowerCase();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Admin</title>
<style>
  :root{
    --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.75);
    --red:#e3342f; --red2:#ff4a44;
    --radius:14px;
  }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1200px;margin:0 auto;padding:16px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .btn{
    border:1px solid rgba(255,255,255,.18);
    background:rgba(255,255,255,.06);
    color:#fff;font-weight:900;
    border-radius:999px;
    padding:10px 14px;
    cursor:pointer;
    text-decoration:none;
    white-space:nowrap;
  }
  .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);}
  .btn.ghost{background:transparent;}
  input,select{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid rgba(255,255,255,.18);
    background:rgba(0,0,0,.25);
    color:#fff;
    font-size:16px;
  }
  .muted{color:var(--muted);}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;}
  th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
  .toast.show{display:block;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
  .stack{display:flex;gap:8px;flex-wrap:wrap;}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div>
        <div style="font-weight:1000;font-size:22px;">Admin</div>
        <div class="muted">Signed in as <strong>${escapeHtml(email)}</strong></div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>

    <div class="hr"></div>

    <div class="row" style="justify-content:space-between;">
      <div style="flex:1 1 420px;">
        <div style="font-weight:900;">Run keys + tracking</div>
        <div class="muted" id="runInfo">Loading…</div>
        <div class="row" style="margin-top:10px;">
          <button class="btn primary" id="dlLocal">Download Local CSV</button>
          <button class="btn primary" id="dlOwen">Download Owen CSV</button>
        </div>
        <div class="row" style="margin-top:10px;">
          <button class="btn" id="trkStartLocal">Start Tracking (Local)</button>
          <button class="btn" id="trkStopLocal">Stop Tracking (Local)</button>
          <button class="btn" id="trkStartOwen">Start Tracking (Owen)</button>
          <button class="btn" id="trkStopOwen">Stop Tracking (Owen)</button>
          <a class="btn ghost" id="driverLocal" href="#">Driver Mode (Local)</a>
          <a class="btn ghost" id="driverOwen" href="#">Driver Mode (Owen)</a>
        </div>
        <div class="muted" style="margin-top:10px;">Auto-start: setting any order to <strong>shopping</strong> starts tracking for that run.</div>
      </div>

      <div style="flex:1 1 420px;">
        <div style="font-weight:900;">Search</div>
        <div class="muted">OrderId / name / town / phone / email / postal.</div>
        <div class="row" style="margin-top:10px;">
          <div style="flex:1 1 260px;"><input id="q" placeholder="e.g., TGR-00123 or Bullock or Tobermory"></div>
          <div style="flex:0 0 220px;">
            <select id="state">
              <option value="">Any status</option>
              <option value="submitted">submitted</option>
              <option value="confirmed">confirmed</option>
              <option value="shopping">shopping</option>
              <option value="packed">packed</option>
              <option value="out_for_delivery">out_for_delivery</option>
              <option value="delivered">delivered</option>
              <option value="issue">issue</option>
              <option value="cancelled">cancelled</option>
            </select>
          </div>
          <button class="btn" id="searchBtn">Search</button>
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="muted" id="countLine">Loading…</div>
    <div style="overflow:auto;margin-top:10px;">
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Customer</th>
            <th>Run</th>
            <th>Address</th>
            <th>Status</th>
            <th>Fees</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  const toast = (msg)=>{
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(()=>el.classList.remove("show"), 3500);
  };

  const api = {
    runs: "/api/runs/active",
    list: "/api/admin/orders",
    status: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/status",
    cancel: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/cancel",
    del: (id)=> "/api/admin/orders/" + encodeURIComponent(id),
    trkStart: (rk)=> "/api/admin/tracking/" + encodeURIComponent(rk) + "/start",
    trkStop: (rk)=> "/api/admin/tracking/" + encodeURIComponent(rk) + "/stop",
  };

  let runKeys = { local:"", owen:"" };

  async function fetchRuns(){
    const r = await fetch(api.runs, { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Runs failed");

    runKeys.local = d.runs?.local?.runKey || "";
    runKeys.owen = d.runs?.owen?.runKey || "";

    document.getElementById("runInfo").textContent =
      "Local: " + runKeys.local + " • Owen: " + runKeys.owen;

    document.getElementById("driverLocal").href = "/driver?runKey=" + encodeURIComponent(runKeys.local);
    document.getElementById("driverOwen").href = "/driver?runKey=" + encodeURIComponent(runKeys.owen);
  }

  function dl(runKey){
    if(!runKey) return toast("Run key missing");
    window.location.href = "/api/admin/routific/export-csv?runKey=" + encodeURIComponent(runKey);
  }

  async function setTracking(runKey, on){
    if(!runKey) return toast("Run key missing");
    const url = on ? api.trkStart(runKey) : api.trkStop(runKey);
    const r = await fetch(url, { method:"POST", credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Tracking toggle failed");
    toast((on ? "Tracking started: " : "Tracking stopped: ") + runKey);
  }

  async function fetchOrders(){
    const q = document.getElementById("q").value.trim();
    const state = document.getElementById("state").value;

    const url = new URL(location.origin + api.list);
    if(q) url.searchParams.set("q", q);
    if(state) url.searchParams.set("state", state);
    url.searchParams.set("limit", "80");

    const r = await fetch(url.toString(), { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Orders failed");

    const items = d.items || [];
    document.getElementById("countLine").textContent = items.length + " orders shown";

    const tbody = document.getElementById("rows");
    tbody.innerHTML = "";

    items.forEach(o=>{
      const tr = document.createElement("tr");
      const fees = (o.pricingSnapshot && typeof o.pricingSnapshot.totalFees==="number") ? o.pricingSnapshot.totalFees : 0;

      tr.innerHTML = \`
        <td><div style="font-weight:1000;">\${o.orderId}</div><div class="muted" style="font-size:12px;">\${new Date(o.createdAt).toLocaleString()}</div></td>
        <td><div style="font-weight:900;">\${o.customer?.fullName || "—"}</div><div class="muted" style="font-size:12px;">\${o.customer?.phone || "—"}</div></td>
        <td><span class="pill">\${o.runType}</span><div class="muted" style="font-size:12px;margin-top:4px;">\${o.runKey}</div></td>
        <td><div style="font-weight:900;">\${o.address?.town || "—"} (Zone \${o.address?.zone || "—"})</div><div class="muted" style="font-size:12px;">\${o.address?.streetAddress || "—"} • \${o.address?.postalCode || ""}</div></td>
        <td><span class="pill">\${o.status?.state || "submitted"}</span><div class="muted" style="font-size:12px;margin-top:4px;">\${o.status?.note || ""}</div></td>
        <td>$\${fees.toFixed(2)}</td>
        <td>
          <div class="stack">
            <button class="btn" data-setstate="\${o.orderId}" data-state="confirmed">Confirmed</button>
            <button class="btn" data-setstate="\${o.orderId}" data-state="shopping">Shopping</button>
            <button class="btn" data-setstate="\${o.orderId}" data-state="packed">Packed</button>
            <button class="btn" data-setstate="\${o.orderId}" data-state="out_for_delivery">Out</button>
            <button class="btn" data-setstate="\${o.orderId}" data-state="delivered">Delivered</button>
            <button class="btn" data-setstate="\${o.orderId}" data-state="issue">Issue</button>
            <button class="btn" data-cancel="\${o.orderId}">Cancel</button>
            <button class="btn" data-del="\${o.orderId}">Delete</button>
          </div>
        </td>
      \`;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll("[data-setstate]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-setstate");
        const st = btn.getAttribute("data-state");
        const note = prompt("Status note (optional):", "") || "";

        const r = await fetch(api.status(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ state: st, note }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Status update failed");
        toast("Updated " + id + " → " + st);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });

    tbody.querySelectorAll("[data-cancel]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-cancel");
        const reason = prompt("Cancel reason:", "Cancelled by admin") || "";
        const r = await fetch(api.cancel(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ reason }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Cancel failed");
        toast("Cancelled " + id);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });

    tbody.querySelectorAll("[data-del]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-del");
        const ok = confirm("Delete " + id + "? This cannot be undone.");
        if(!ok) return;
        const r = await fetch(api.del(id), { method:"DELETE", credentials:"include" });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Delete failed");
        toast("Deleted " + id);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });
  }

  document.getElementById("searchBtn").addEventListener("click", ()=>fetchOrders().catch(e=>toast(String(e.message||e))));
  document.getElementById("dlLocal").addEventListener("click", ()=>dl(runKeys.local));
  document.getElementById("dlOwen").addEventListener("click", ()=>dl(runKeys.owen));

  document.getElementById("trkStartLocal").addEventListener("click", ()=>setTracking(runKeys.local, true));
  document.getElementById("trkStopLocal").addEventListener("click", ()=>setTracking(runKeys.local, false));
  document.getElementById("trkStartOwen").addEventListener("click", ()=>setTracking(runKeys.owen, true));
  document.getElementById("trkStopOwen").addEventListener("click", ()=>setTracking(runKeys.owen, false));

  fetchRuns().then(fetchOrders).catch(e=>toast(String(e.message||e)));
</script>

</body>
</html>`);
});

// =========================
// ROOT + BOOT
// =========================
app.get("/", (_req, res) => res.send("TGR backend up"));

async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");
  app.listen(PORT, () => console.log("Server running on port", PORT));
}
main().catch((err) => {
  console.error(err);
  process.exit(1);
});