// ======= server.js (FULL FILE) — TGR backend =======
// Google OAuth, profile onboarding, biweekly runs, estimator, orders, cancel tokens
// FULL ADMIN COMMAND CENTER + endpoints (search/view/status/payments/hold/flags/bulk/export/print/tracking/email)
// MEMBER PORTAL (/member) restored (order list + cancel before cutoff)
// AddressComplete proxy endpoints kept
//
// Order IDs: TGR-LOC-YYYYMMDD-XXXXXX or TGR-OWEN-YYYYMMDD-XXXXXX

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

const postmark = require("postmark");

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

// tracking token secret
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

// Postmark outbound (optional)
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || "";
const POSTMARK_FROM_EMAIL = process.env.POSTMARK_FROM_EMAIL || "orders@tobermorygroceryrun.ca";
const POSTMARK_MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || "outbound";

const pmClient = POSTMARK_SERVER_TOKEN ? new postmark.ServerClient(POSTMARK_SERVER_TOKEN) : null;

// Square pay links (member portal quick buttons)
const SQUARE_PAY_GROCERIES_LINK =
  process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8";
const SQUARE_PAY_FEES_LINK =
  process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs";

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
// MODELS
// =========================
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

    // Admin control fields
    hold: { type: Boolean, default: false },
    flags: {
      type: {
        idRequired: { type: Boolean, default: false },
        prescription: { type: Boolean, default: false },
        alcohol: { type: Boolean, default: false },
        bulky: { type: Boolean, default: false },
        newCustomerDepositRequired: { type: Boolean, default: false },
        needsContact: { type: Boolean, default: false },
      },
      default: {},
    },

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
        status: { type: String, default: "unpaid" }, // unpaid|paid
        note: { type: String, default: "" },
        paidAt: { type: Date, default: null },
      },
      groceries: {
        status: { type: String, default: "unpaid" }, // unpaid|paid|deposit_paid
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

    adminLog: {
      type: [{ at: Date, by: String, action: String, meta: Object }],
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
    lastLat: { type: Number, default: null },
    lastLng: { type: Number, default: null },
    lastHeading: { type: Number, default: null },
    lastSpeed: { type: Number, default: null },
    lastAccuracy: { type: Number, default: null },
    lastAt: { type: Date, default: null },
    updatedBy: { type: String, default: "system" },
  },
  { timestamps: true }
);

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

  return (
    !!fullName &&
    !!phone &&
    !!contactPref &&
    contactAuth &&
    hasAddress &&
    consentsOk
  );
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

// ===== Postmark helper (optional) =====
async function pmSend(to, subject, htmlBody, textBody) {
  try {
    const rcpt = String(to || "").trim();
    if (!pmClient || !POSTMARK_FROM_EMAIL || !rcpt) return;
    await pmClient.sendEmail({
      From: POSTMARK_FROM_EMAIL,
      To: rcpt,
      Subject: subject,
      HtmlBody: htmlBody,
      TextBody: textBody || "",
      MessageStream: POSTMARK_MESSAGE_STREAM,
    });
  } catch (e) {
    console.error("Postmark send failed:", String(e));
  }
}

function money(n) {
  const x = Number(n || 0);
  return x.toFixed(2);
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
    const runKey = segs.slice(1, -1).join(".");

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

// ===== Robust run-prefixed order ID generator =====
// Format: TGR-LOC-YYYYMMDD-XXXXXX or TGR-OWEN-YYYYMMDD-XXXXXX
async function nextOrderId(runType, runKey) {
  const type = String(runType || "").toLowerCase();
  const prefix = type === "owen" ? "OWEN" : "LOC";

  const datePart = String(runKey || "").slice(0, 10).replaceAll("-", ""); // YYYYMMDD
  const runDate = /^\d{8}$/.test(datePart) ? datePart : dayjs().tz(TZ).format("YYYYMMDD");

  for (let i = 0; i < 24; i++) {
    const n = crypto.randomInt(0, 1000000);
    const rand = String(n).padStart(6, "0");
    const candidate = `TGR-${prefix}-${runDate}-${rand}`;
    const exists = await Order.exists({ orderId: candidate });
    if (!exists) return candidate;
  }

  const n = crypto.randomInt(0, 100000000);
  return `TGR-${prefix}-${runDate}-${String(n).padStart(8, "0")}`;
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

// =========================
// RUN SCHEDULING (biweekly, DB-driven)
// =========================
function runKeyToDayjs(runKey) {
  try {
    const dateStr = String(runKey || "").slice(0, 10); // YYYY-MM-DD
    const d = dayjs(dateStr).tz(TZ);
    return d.isValid() ? d : null;
  } catch {
    return null;
  }
}

function nextDow(targetDow, from) {
  let d = dayjs(from).tz(TZ);
  const current = d.day();
  let diff = (targetDow - current + 7) % 7;
  if (diff === 0) diff = 7;
  return d.add(diff, "day");
}

function computeTimesForDelivery(deliveryDayjs, type) {
  const delivery = dayjs(deliveryDayjs).tz(TZ);
  if (type === "local") {
    const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0); // Thu 6pm
    const opens = delivery.subtract(5, "day").hour(0).minute(0).second(0).millisecond(0); // Mon 12am
    return { delivery, cutoff, opens };
  }
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
  if (run.minLogic === "AND") return run.bookedOrdersCount >= run.minOrders && run.bookedFeesTotal >= run.minFees;
  return run.bookedOrdersCount >= run.minOrders || run.bookedFeesTotal >= run.minFees;
}

async function getOrCreateNextRun(type) {
  const now = nowTz();

  // Prefer an existing run that has NOT passed cutoff yet
  let existing = await Run.findOne({ type, cutoffAt: { $gt: now.toDate() } })
    .sort({ opensAt: 1 })
    .lean();

  // If found but opensAt is still in the future, force it open now
  if (existing) {
    const opensAt = dayjs(existing.opensAt).tz(TZ);
    const cutoffAt = dayjs(existing.cutoffAt).tz(TZ);

    if (now.isBefore(cutoffAt) && now.isBefore(opensAt)) {
      const forced = now.subtract(1, "minute").toDate();
      await Run.updateOne({ runKey: existing.runKey }, { $set: { opensAt: forced } });
      existing.opensAt = forced;
    }
    return existing;
  }

  // No upcoming run in DB: create one
  const latest = await Run.findOne({ type }).sort({ opensAt: -1 }).lean();

  let delivery;
  if (latest?.runKey) {
    const lastDelivery = runKeyToDayjs(latest.runKey);
    delivery = (lastDelivery || now).add(14, "day");
  } else {
    delivery = type === "local" ? nextDow(6, now) : nextDow(0, now);
  }

  let { cutoff, opens } = computeTimesForDelivery(delivery, type);

  if (opens.isAfter(now)) opens = now.subtract(1, "minute");

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

// =========================
// TRACKING
// =========================
async function ensureTrackingDoc(runKey) {
  const t = await Tracking.findOneAndUpdate(
    { runKey },
    { $setOnInsert: { runKey, enabled: false, startedAt: null, stoppedAt: null, updatedBy: "system" } },
    { upsert: true, new: true }
  ).lean();
  return t;
}

// public tracking: requires token; only works if order active and tracking enabled
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

// =========================
// AddressComplete proxy
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
        cutoffAtISO: run.cutoffAt,
        opensAtISO: run.opensAt,
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

    const orderId = await nextOrderId(runType, run.runKey);
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

    const maxSlots = run.maxSlots || 12;
    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedOrdersCount: { $lt: maxSlots } },
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees }, $set: { lastRecalcAt: new Date() } },
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    const created = await Order.create({
      orderId,
      runKey: run.runKey,
      runType,
      hold: false,
      flags: {},
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
      adminLog: [{ at: new Date(), by: "system", action: "order_created", meta: { runKey: run.runKey } }],
    });

    const cancelUntilMs = cutoffAt.toDate().getTime();
    const cancelToken = signCancelToken(orderId, cancelUntilMs);
    const cancelUntilLocal = fmtLocal(cutoffAt.toDate());

    // Optional email: order received (only if Postmark configured)
    pmSend(
      created.customer?.email,
      `TGR Order Received: ${created.orderId}`,
      `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
        <h2 style="margin:0 0 10px;">Order received ✅</h2>
        <p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(created.orderId)}</p>
        <p style="margin:0 0 10px;"><strong>Run:</strong> ${escapeHtml(created.runKey)} (${escapeHtml(created.runType)})</p>
        <p style="margin:0 0 10px;"><strong>Fees estimate:</strong> $${escapeHtml(money(created.pricingSnapshot?.totalFees || 0))}</p>
        <p style="margin:0;">You can view orders in your Member Portal after signing in.</p>
      </div>`,
      `Order received\nOrder ID: ${created.orderId}\nRun: ${created.runKey} (${created.runType})\nFees estimate: $${money(created.pricingSnapshot?.totalFees || 0)}`
    );

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
      return res.status(403).json({ ok: false, error: "Cancellation window closed (past cutoff)." });
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
    order.adminLog.push({ at: new Date(), by: "customer", action: "cancel", meta: {} });

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// MEMBER PORTAL (RESTORED)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const name = String(req.user?.name || "").trim();

    const orders = await Order.find({ "customer.email": email })
      .sort({ createdAt: -1 })
      .limit(60)
      .lean();

    const runKeys = Array.from(new Set(orders.map(o => o.runKey).filter(Boolean)));
    const runs = await Run.find({ runKey: { $in: runKeys } }).lean();
    const runByKey = new Map(runs.map(r => [r.runKey, r]));

    const now = nowTz();

    const rows = orders.map(o => {
      const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
      const status = o.status?.state || "submitted";
      const run = runByKey.get(o.runKey);
      const cutoffAt = run?.cutoffAt ? dayjs(run.cutoffAt).tz(TZ) : null;
      const cancelOpen = cutoffAt ? now.isBefore(cutoffAt) : false;

      let cancelHtml = `<span class="muted">Not available</span>`;
      if (ACTIVE_STATES.has(status) && cancelOpen) {
        const token = signCancelToken(o.orderId, cutoffAt.toDate().getTime());
        cancelHtml = `<button class="btn" data-cancel="${escapeHtml(o.orderId)}" data-token="${escapeHtml(token)}">Cancel</button>`;
      } else if (status === "cancelled") {
        cancelHtml = `<span class="pill">Cancelled</span>`;
      } else if (!cancelOpen && ACTIVE_STATES.has(status)) {
        cancelHtml = `<span class="muted">Past cutoff</span>`;
      }

      // Tracking link appears only when tracking is enabled AND order is active
      let trackingHtml = `<span class="muted">—</span>`;
      const canTrack = ACTIVE_STATES.has(status);
      if (canTrack && run?.runKey) {
        // token expires at cutoff+1day
        const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf();
        const tkn = signTrackingToken(o.orderId, run.runKey, expMs);
        trackingHtml = `<a class="btn" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=home" onclick="return false;" data-track="${escapeHtml(run.runKey)}" data-token="${escapeHtml(tkn)}">Copy link</a>`;
      }

      return `
        <tr>
          <td><div style="font-weight:1000;">${escapeHtml(o.orderId)}</div><div class="muted" style="font-size:12px;">${escapeHtml(fmtLocal(o.createdAt))}</div></td>
          <td><div style="font-weight:900;">${escapeHtml(o.address?.town || "")} (Zone ${escapeHtml(o.address?.zone || "")})</div>
              <div class="muted" style="font-size:12px;">${escapeHtml(o.address?.streetAddress || "")} • ${escapeHtml(o.address?.postalCode || "")}</div></td>
          <td><span class="pill">${escapeHtml(o.runType || "")}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.runKey || "")}</div></td>
          <td><span class="pill">${escapeHtml(status)}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.status?.note || "")}</div></td>
          <td>$${escapeHtml(fees)}</td>
          <td>${trackingHtml}</td>
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
  .wrap{max-width:1150px;margin:0 auto;padding:16px;}
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

  async function copy(text){
    try{ await navigator.clipboard.writeText(text); return true; } catch { return false; }
  }

  document.querySelectorAll("[data-cancel]").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      cancelOrder(btn.getAttribute("data-cancel"), btn.getAttribute("data-token"));
    });
  });

  document.querySelectorAll("[data-track]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      const runKey = btn.getAttribute("data-track");
      const token = btn.getAttribute("data-token");
      const url = "${escapeHtml(PUBLIC_SITE_URL)}" + "/track.html?runKey=" + encodeURIComponent(runKey) + "&token=" + encodeURIComponent(token);
      if (await copy(url)) toast("Tracking link copied ✅");
      else toast("Copy failed");
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
function adminBy(req) {
  return String(req.user?.email || "admin").toLowerCase();
}

function addAdminLog(order, by, action, meta) {
  order.adminLog = Array.isArray(order.adminLog) ? order.adminLog : [];
  order.adminLog.push({ at: new Date(), by: by || "admin", action: String(action || ""), meta: meta || {} });
}

function buildOrderFilterFromQuery(qs) {
  const q = String(qs.q || "").trim();
  const state = String(qs.state || "").trim();
  const runKey = String(qs.runKey || "").trim();
  const zone = String(qs.zone || "").trim();
  const town = String(qs.town || "").trim();
  const unpaidFees = String(qs.unpaidFees || "").trim() === "1";
  const hold = String(qs.hold || "").trim() === "1";
  const flag = String(qs.flag || "").trim(); // idRequired/prescription/alcohol/bulky/newCustomerDepositRequired/needsContact

  const filter = {};
  if (runKey) filter.runKey = runKey;
  if (state) filter["status.state"] = state;
  if (zone) filter["address.zone"] = zone;
  if (town) filter["address.town"] = new RegExp("^" + town.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$", "i");
  if (unpaidFees) filter["payments.fees.status"] = "unpaid";
  if (hold) filter["hold"] = true;
  if (flag) filter[`flags.${flag}`] = true;

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

  return filter;
}

app.get("/api/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit || 120)));
    const filter = buildOrderFilterFromQuery(req.query);

    const items = await Order.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const o = await Order.findOne({ orderId }).lean();
    if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
    res.json({ ok: true, order: o });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const state = String(req.body?.state || "").trim();
    const note = String(req.body?.note || "").trim();
    const by = adminBy(req);

    if (!AllowedStates.includes(state)) {
      return res.status(400).json({ ok: false, error: "Invalid state" });
    }

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.status.state = state;
    order.status.note = note;
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state, note, at: new Date(), by });

    addAdminLog(order, by, "status", { state, note });
    await order.save();

    // Optional: email notify on confirmed/out_for_delivery/delivered
    if (state === "confirmed") {
      pmSend(
        order.customer?.email,
        `TGR Order Confirmed: ${order.orderId}`,
        `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
          <h2 style="margin:0 0 10px;">Order confirmed ✅</h2>
          <p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(order.orderId)}</p>
          <p style="margin:0 0 10px;">Please pay service & delivery fees before shopping begins.</p>
          <p style="margin:0 0 8px;"><a href="${escapeHtml(SQUARE_PAY_FEES_LINK)}">Pay Service & Delivery Fees</a></p>
          <p style="margin:0 0 8px;"><a href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}">Pay Grocery Total</a></p>
        </div>`,
        `Order confirmed: ${order.orderId}\nPay fees: ${SQUARE_PAY_FEES_LINK}\nPay groceries: ${SQUARE_PAY_GROCERIES_LINK}`
      );
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/payments", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const by = adminBy(req);

    const feesStatus = String(req.body?.feesStatus || "").trim(); // unpaid|paid
    const groceriesStatus = String(req.body?.groceriesStatus || "").trim(); // unpaid|paid|deposit_paid
    const note = String(req.body?.note || "").trim();

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    if (feesStatus) {
      order.payments.fees.status = feesStatus;
      order.payments.fees.paidAt = feesStatus === "paid" ? new Date() : null;
    }
    if (groceriesStatus) {
      order.payments.groceries.status = groceriesStatus;
      order.payments.groceries.paidAt = (groceriesStatus === "paid" || groceriesStatus === "deposit_paid") ? new Date() : null;
    }
    if (note) {
      order.payments.fees.note = note;
      order.payments.groceries.note = note;
    }

    addAdminLog(order, by, "payments", { feesStatus, groceriesStatus, note });
    await order.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/hold", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const by = adminBy(req);
    const hold = !!req.body?.hold;

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.hold = hold;
    addAdminLog(order, by, "hold", { hold });
    await order.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/flags", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const by = adminBy(req);

    const flags = req.body?.flags || {};
    const allowed = ["idRequired","prescription","alcohol","bulky","newCustomerDepositRequired","needsContact"];

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.flags = order.flags || {};
    for (const k of allowed) {
      if (k in flags) order.flags[k] = !!flags[k];
    }

    addAdminLog(order, by, "flags", { flags: order.flags });
    await order.save();
    res.json({ ok: true, flags: order.flags });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/cancel", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const reason = String(req.body?.reason || "").trim() || "Cancelled by admin";
    const by = adminBy(req);

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

    addAdminLog(order, by, "cancel", { reason });
    await order.save();

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.delete("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const by = adminBy(req);

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
    // no adminLog possible after delete
    res.json({ ok: true, deleted: orderId, by });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Bulk actions
app.post("/api/admin/bulk/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [];
    const state = String(req.body?.state || "").trim();
    const note = String(req.body?.note || "").trim();
    const by = adminBy(req);

    if (!AllowedStates.includes(state)) return res.status(400).json({ ok: false, error: "Invalid state" });
    if (!ids.length) return res.status(400).json({ ok: false, error: "No orderIds" });

    const orders = await Order.find({ orderId: { $in: ids.map(s => s.toUpperCase()) } });
    for (const o of orders) {
      o.status.state = state;
      o.status.note = note;
      o.status.updatedAt = new Date();
      o.status.updatedBy = by;
      o.statusHistory.push({ state, note, at: new Date(), by });
      addAdminLog(o, by, "bulk_status", { state, note });
      await o.save();
    }

    res.json({ ok: true, updated: orders.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/bulk/cancel", requireLogin, requireAdmin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [];
    const reason = String(req.body?.reason || "").trim() || "Cancelled by admin (bulk)";
    const by = adminBy(req);

    if (!ids.length) return res.status(400).json({ ok: false, error: "No orderIds" });

    const orders = await Order.find({ orderId: { $in: ids.map(s => s.toUpperCase()) } });
    for (const o of orders) {
      const wasActive = ACTIVE_STATES.has(o.status?.state || "submitted");
      if (wasActive) {
        const fees = Number(o.pricingSnapshot?.totalFees || 0);
        await Run.updateOne(
          { runKey: o.runKey },
          { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }
        );
      }
      o.status.state = "cancelled";
      o.status.note = reason;
      o.status.updatedAt = new Date();
      o.status.updatedBy = by;
      o.statusHistory.push({ state: "cancelled", note: reason, at: new Date(), by });
      addAdminLog(o, by, "bulk_cancel", { reason });
      await o.save();
    }

    res.json({ ok: true, cancelled: orders.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/bulk/hold", requireLogin, requireAdmin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [];
    const hold = !!req.body?.hold;
    const by = adminBy(req);

    if (!ids.length) return res.status(400).json({ ok: false, error: "No orderIds" });

    const orders = await Order.find({ orderId: { $in: ids.map(s => s.toUpperCase()) } });
    for (const o of orders) {
      o.hold = hold;
      addAdminLog(o, by, "bulk_hold", { hold });
      await o.save();
    }
    res.json({ ok: true, updated: orders.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/bulk/fees-paid", requireLogin, requireAdmin, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [];
    const by = adminBy(req);
    if (!ids.length) return res.status(400).json({ ok: false, error: "No orderIds" });

    const orders = await Order.find({ orderId: { $in: ids.map(s => s.toUpperCase()) } });
    for (const o of orders) {
      o.payments.fees.status = "paid";
      o.payments.fees.paidAt = new Date();
      addAdminLog(o, by, "bulk_fees_paid", {});
      await o.save();
    }
    res.json({ ok: true, updated: orders.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Tracking admin controls
app.post("/api/admin/tracking/:runKey/start", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = adminBy(req);
    const t = await ensureTrackingDoc(runKey);
    await Tracking.updateOne(
      { runKey },
      { $set: { enabled: true, startedAt: new Date(), stoppedAt: null, updatedBy: by } }
    );
    res.json({ ok: true, runKey });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/tracking/:runKey/stop", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = adminBy(req);
    await ensureTrackingDoc(runKey);
    await Tracking.updateOne(
      { runKey },
      { $set: { enabled: false, stoppedAt: new Date(), updatedBy: by } }
    );
    res.json({ ok: true, runKey });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Use this endpoint from your phone (while logged into admin) to update live GPS
app.post("/api/admin/tracking/:runKey/update", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = adminBy(req);

    const lat = Number(req.body?.lat);
    const lng = Number(req.body?.lng);
    const heading = Number(req.body?.heading);
    const speed = Number(req.body?.speed);
    const accuracy = Number(req.body?.accuracy);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ ok: false, error: "lat/lng required" });
    }

    await ensureTrackingDoc(runKey);
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

// Create a tracking link for an order (admin)
app.get("/api/admin/orders/:orderId/tracking-link", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const o = await Order.findOne({ orderId }).lean();
    if (!o) return res.status(404).json({ ok: false, error: "Order not found" });

    const run = await Run.findOne({ runKey: o.runKey }).lean();
    if (!run) return res.status(404).json({ ok: false, error: "Run not found" });

    const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf();
    const token = signTrackingToken(o.orderId, run.runKey, expMs);

    const url = `${PUBLIC_SITE_URL}/track.html?runKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(token)}`;
    res.json({ ok: true, url });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Email notify templates (admin)
app.post("/api/admin/notify", requireLogin, requireAdmin, async (req, res) => {
  try {
    const template = String(req.body?.template || "").trim(); // confirmed|out|generic
    const ids = Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [];
    const by = adminBy(req);

    if (!pmClient) return res.status(400).json({ ok: false, error: "Postmark not configured (POSTMARK_SERVER_TOKEN missing)." });
    if (!ids.length) return res.status(400).json({ ok: false, error: "No orderIds" });

    const orders = await Order.find({ orderId: { $in: ids.map(s => s.toUpperCase()) } }).lean();
    let sent = 0;

    for (const o of orders) {
      const to = o.customer?.email;
      if (!to) continue;

      let subject = `TGR Update: ${o.orderId}`;
      let html = `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
        <h2 style="margin:0 0 10px;">TGR update</h2>
        <p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(o.orderId)}</p>
      </div>`;
      let text = `TGR update\nOrder ID: ${o.orderId}`;

      if (template === "confirmed") {
        subject = `TGR Order Confirmed: ${o.orderId}`;
        html = `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
          <h2 style="margin:0 0 10px;">Order confirmed ✅</h2>
          <p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(o.orderId)}</p>
          <p style="margin:0 0 10px;">Pay service & delivery fees before shopping begins:</p>
          <p style="margin:0 0 8px;"><a href="${escapeHtml(SQUARE_PAY_FEES_LINK)}">Pay Service & Delivery Fees</a></p>
          <p style="margin:0 0 8px;"><a href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}">Pay Grocery Total</a></p>
        </div>`;
        text = `Order confirmed: ${o.orderId}\nPay fees: ${SQUARE_PAY_FEES_LINK}\nPay groceries: ${SQUARE_PAY_GROCERIES_LINK}`;
      } else if (template === "out") {
        subject = `TGR Out for Delivery: ${o.orderId}`;
        html = `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
          <h2 style="margin:0 0 10px;">Out for delivery 🚚</h2>
          <p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(o.orderId)}</p>
          <p style="margin:0;">If tracking is enabled, your tracking link will work from the Member Portal.</p>
        </div>`;
        text = `Out for delivery: ${o.orderId}`;
      }

      await pmSend(to, subject, html, text);
      sent++;
    }

    // log (no per-order doc update here to keep it light)
    res.json({ ok: true, sent, by });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Routific CSV export
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
        o.hold ? "HOLD: yes" : "",
        o.flags?.idRequired ? "FLAG: ID required" : "",
        o.flags?.prescription ? "FLAG: prescription" : "",
        o.flags?.bulky ? "FLAG: bulky" : "",
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

// Print pick lists (per runKey)
app.get("/api/admin/print/picks", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.query.runKey || "").trim();
    if (!runKey) return res.status(400).send("Missing runKey");

    const orders = await Order.find({ runKey }).sort({ createdAt: 1 }).lean();

    const blocks = orders.map(o => {
      const addr =
        `${o.address?.streetAddress || ""}${o.address?.unit ? (" " + o.address.unit) : ""}, ` +
        `${o.address?.town || ""}, ON ${o.address?.postalCode || ""}`.trim();

      const extra = (o.stores?.extra || []).length ? (o.stores.extra || []).join(", ") : "—";
      const flags = [
        o.hold ? "HOLD" : "",
        o.flags?.idRequired ? "ID" : "",
        o.flags?.prescription ? "RX" : "",
        o.flags?.alcohol ? "ALC" : "",
        o.flags?.bulky ? "BULKY" : "",
      ].filter(Boolean).join(" • ") || "—";

      return `
        <div class="card">
          <div class="top">
            <div>
              <div class="oid">${escapeHtml(o.orderId)}</div>
              <div class="muted">${escapeHtml(o.customer?.fullName || "")} • ${escapeHtml(o.customer?.phone || "")}</div>
              <div class="muted">${escapeHtml(addr)}</div>
            </div>
            <div class="meta">
              <div><strong>Zone:</strong> ${escapeHtml(o.address?.zone || "")}</div>
              <div><strong>Store:</strong> ${escapeHtml(o.stores?.primary || "")}</div>
              <div><strong>Extra:</strong> ${escapeHtml(extra)}</div>
              <div><strong>Flags:</strong> ${escapeHtml(flags)}</div>
              <div><strong>Fees:</strong> $${escapeHtml(money(o.pricingSnapshot?.totalFees || 0))}</div>
            </div>
          </div>
          <div class="hr"></div>
          <div class="list">${escapeHtml(o.list?.groceryListText || "").replaceAll("\n","<br>")}</div>
          <div class="hr"></div>
          <div class="muted"><strong>Notes:</strong> ${escapeHtml(o.status?.note || "")}</div>
        </div>
      `;
    }).join("");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pick Lists ${escapeHtml(runKey)}</title>
<style>
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#111;color:#fff;}
  .wrap{max-width:1000px;margin:0 auto;padding:16px;}
  .card{border:1px solid rgba(255,255,255,.18);border-radius:14px;background:rgba(255,255,255,.06);padding:12px;margin-bottom:12px;page-break-inside:avoid;}
  .top{display:flex;gap:12px;justify-content:space-between;flex-wrap:wrap;}
  .oid{font-weight:1000;font-size:20px;}
  .muted{color:rgba(255,255,255,.75);font-size:13px;}
  .meta{min-width:260px;font-size:14px;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:10px 0;}
  .list{white-space:normal;font-size:15px;line-height:1.35;}
  @media print{
    body{background:#fff;color:#000;}
    .card{background:#fff;border:1px solid #ccc;}
    .muted{color:#333;}
  }
</style>
</head>
<body>
<div class="wrap">
  <h2 style="margin:0 0 10px;">Pick Lists — ${escapeHtml(runKey)}</h2>
  <div class="muted" style="margin-bottom:12px;">Print this page. One card per order.</div>
  ${blocks || "<div class='muted'>No orders.</div>"}
</div>
</body></html>`);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// =========================
// FULL ADMIN COMMAND CENTER PAGE
// =========================
app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  const email = String(req.user?.email || "").toLowerCase();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Admin Command Center</title>
<style>
  :root{
    --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.75);
    --red:#e3342f; --red2:#ff4a44;
    --radius:14px;
  }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1280px;margin:0 auto;padding:16px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
  @media (max-width: 980px){ .grid{grid-template-columns:1fr;} }
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
  input,select,textarea{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid rgba(255,255,255,.18);
    background:rgba(0,0,0,.25);
    color:#fff;
    font-size:16px;
  }
  textarea{min-height:90px;}
  .muted{color:var(--muted);}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;}
  th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
  .toast.show{display:block;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
  .kpi{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;}
  .kpi .pill{font-size:13px;}
  .small{font-size:13px;}
  .right{margin-left:auto;}
  .danger{border-color:rgba(227,52,47,.55);background:rgba(227,52,47,.10);}
  .ok{border-color:rgba(60,200,120,.40);background:rgba(60,200,120,.10);}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div>
        <div style="font-weight:1000;font-size:22px;">Admin Command Center</div>
        <div class="muted">Signed in as <strong>${escapeHtml(email)}</strong></div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>
    <div class="hr"></div>

    <div class="grid">
      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;font-size:18px;">Run dashboard</div>
        <div class="muted">Cutoffs, minimums, slots, tracking controls, exports.</div>
        <div class="hr"></div>

        <div class="row">
          <div style="flex:1 1 280px;">
            <div style="font-weight:900;">Local run</div>
            <div class="muted small" id="rkLocal">—</div>
            <div class="kpi">
              <span class="pill" id="localOpen">—</span>
              <span class="pill" id="localSlots">Slots —</span>
              <span class="pill" id="localMin">Min —</span>
              <span class="pill" id="localFees">Fees —</span>
            </div>
            <div class="muted small" id="localCutoff">—</div>
            <div class="row" style="margin-top:10px;">
              <button class="btn" id="localExport">Export Routific</button>
              <button class="btn" id="localPrint">Print picks</button>
              <button class="btn" id="localTrackStart">Start tracking</button>
              <button class="btn" id="localTrackStop">Stop tracking</button>
            </div>
          </div>

          <div style="flex:1 1 280px;">
            <div style="font-weight:900;">Owen run</div>
            <div class="muted small" id="rkOwen">—</div>
            <div class="kpi">
              <span class="pill" id="owenOpen">—</span>
              <span class="pill" id="owenSlots">Slots —</span>
              <span class="pill" id="owenMin">Min —</span>
              <span class="pill" id="owenFees">Fees —</span>
            </div>
            <div class="muted small" id="owenCutoff">—</div>
            <div class="row" style="margin-top:10px;">
              <button class="btn" id="owenExport">Export Routific</button>
              <button class="btn" id="owenPrint">Print picks</button>
              <button class="btn" id="owenTrackStart">Start tracking</button>
              <button class="btn" id="owenTrackStop">Stop tracking</button>
            </div>
          </div>
        </div>

        <div class="hr"></div>

        <div class="row">
          <button class="btn primary" id="refreshBtn">Refresh</button>
          <span class="muted small" id="clockLine">—</span>
        </div>
      </div>

      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;font-size:18px;">Search & filters</div>
        <div class="muted">OrderId / name / town / phone / email / postal + advanced filters.</div>
        <div class="hr"></div>

        <div class="row">
          <div style="flex:1 1 260px;"><input id="q" placeholder="Search (TGR-..., name, town, phone, postal)"></div>
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

        <div class="row" style="margin-top:10px;">
          <div style="flex:0 0 230px;">
            <select id="runKey">
              <option value="">Any runKey</option>
            </select>
          </div>
          <div style="flex:0 0 160px;">
            <select id="zone">
              <option value="">Any zone</option>
              <option value="A">A</option><option value="B">B</option><option value="C">C</option><option value="D">D</option>
            </select>
          </div>
          <div style="flex:1 1 220px;">
            <input id="town" placeholder="Town filter (exact)" />
          </div>
        </div>

        <div class="row" style="margin-top:10px;">
          <label class="row small" style="gap:8px;align-items:center;">
            <input type="checkbox" id="unpaidFees" style="width:18px;height:18px;margin:0;">
            Unpaid fees only
          </label>
          <label class="row small" style="gap:8px;align-items:center;">
            <input type="checkbox" id="holdOnly" style="width:18px;height:18px;margin:0;">
            Hold only
          </label>
          <div style="flex:1 1 240px;">
            <select id="flag">
              <option value="">Any flag</option>
              <option value="idRequired">ID required</option>
              <option value="prescription">Prescription</option>
              <option value="alcohol">Alcohol</option>
              <option value="bulky">Bulky</option>
              <option value="newCustomerDepositRequired">New customer deposit</option>
              <option value="needsContact">Needs contact</option>
            </select>
          </div>
        </div>

        <div class="hr"></div>

        <div style="font-weight:1000;">Bulk controls (selected orders)</div>
        <div class="row" style="margin-top:10px;">
          <select id="bulkState" style="flex:0 0 240px;">
            <option value="">Bulk status…</option>
            <option value="confirmed">confirmed</option>
            <option value="shopping">shopping</option>
            <option value="packed">packed</option>
            <option value="out_for_delivery">out_for_delivery</option>
            <option value="delivered">delivered</option>
            <option value="issue">issue</option>
          </select>
          <button class="btn" id="bulkSetStatus">Apply</button>
          <button class="btn" id="bulkFeesPaid">Mark fees paid</button>
          <button class="btn" id="bulkHoldOn">Hold ON</button>
          <button class="btn" id="bulkHoldOff">Hold OFF</button>
          <button class="btn" id="bulkCancel">Cancel</button>
        </div>

        <div class="row" style="margin-top:10px;">
          <select id="notifyTpl" style="flex:0 0 240px;">
            <option value="">Email notify…</option>
            <option value="confirmed">Confirmed + pay links</option>
            <option value="out">Out for delivery</option>
            <option value="generic">Generic update</option>
          </select>
          <button class="btn" id="bulkNotify">Send emails</button>
          <span class="muted small">Emails only (Postmark required).</span>
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="muted" id="countLine">Loading…</div>
    <div style="overflow:auto;margin-top:10px;">
      <table>
        <thead>
          <tr>
            <th>Select</th>
            <th>Order</th>
            <th>Customer</th>
            <th>Run</th>
            <th>Address</th>
            <th>Status</th>
            <th>Fees</th>
            <th>Payments</th>
            <th>Hold/Flags</th>
            <th>Quick</th>
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
    one: (id)=> "/api/admin/orders/" + encodeURIComponent(id),
    status: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/status",
    pay: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/payments",
    hold: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/hold",
    flags: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/flags",
    cancel: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/cancel",
    del: (id)=> "/api/admin/orders/" + encodeURIComponent(id),
    exportCsv: (runKey)=> "/api/admin/routific/export-csv?runKey=" + encodeURIComponent(runKey),
    printPicks: (runKey)=> "/api/admin/print/picks?runKey=" + encodeURIComponent(runKey),
    tStart: (runKey)=> "/api/admin/tracking/" + encodeURIComponent(runKey) + "/start",
    tStop: (runKey)=> "/api/admin/tracking/" + encodeURIComponent(runKey) + "/stop",
    tLink: (id)=> "/api/admin/orders/" + encodeURIComponent(id) + "/tracking-link",
    bulkStatus: "/api/admin/bulk/status",
    bulkCancel: "/api/admin/bulk/cancel",
    bulkHold: "/api/admin/bulk/hold",
    bulkFeesPaid: "/api/admin/bulk/fees-paid",
    notify: "/api/admin/notify",
  };

  let runKeys = { local:"", owen:"" };
  let runsCache = null;

  function pillOpen(isOpen){ return isOpen ? "OPEN ✅" : "CLOSED"; }
  function money(n){ return "$" + Number(n||0).toFixed(2); }

  function msToCountdown(ms){
    const s = Math.max(0, Math.floor(ms/1000));
    const d = Math.floor(s/86400);
    const h = Math.floor((s%86400)/3600);
    const m = Math.floor((s%3600)/60);
    return (d>0 ? (d+"d ") : "") + h + "h " + m + "m";
  }

  async function fetchRuns(){
    const r = await fetch(api.runs, { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Runs failed");
    runsCache = d.runs || null;

    runKeys.local = d.runs?.local?.runKey || "";
    runKeys.owen = d.runs?.owen?.runKey || "";

    const rkSel = document.getElementById("runKey");
    rkSel.innerHTML = '<option value="">Any runKey</option>';
    [runKeys.local, runKeys.owen].filter(Boolean).forEach(k=>{
      const opt = document.createElement("option");
      opt.value = k; opt.textContent = k;
      rkSel.appendChild(opt);
    });

    // populate dashboard
    const L = d.runs.local || {};
    const O = d.runs.owen || {};
    document.getElementById("rkLocal").textContent = L.runKey || "—";
    document.getElementById("rkOwen").textContent = O.runKey || "—";

    const localOpen = document.getElementById("localOpen");
    localOpen.textContent = pillOpen(!!L.isOpen);
    localOpen.className = "pill " + (L.isOpen ? "ok":"danger");

    document.getElementById("localSlots").textContent = "Slots " + (L.slotsRemaining ?? "—");
    document.getElementById("localMin").textContent = L.minimumText || "—";
    document.getElementById("localFees").textContent = "Fees " + money(L.bookedFeesTotal || 0);

    const owenOpen = document.getElementById("owenOpen");
    owenOpen.textContent = pillOpen(!!O.isOpen);
    owenOpen.className = "pill " + (O.isOpen ? "ok":"danger");

    document.getElementById("owenSlots").textContent = "Slots " + (O.slotsRemaining ?? "—");
    document.getElementById("owenMin").textContent = O.minimumText || "—";
    document.getElementById("owenFees").textContent = "Fees " + money(O.bookedFeesTotal || 0);

    document.getElementById("localCutoff").textContent = "Opens: " + (L.opensAtLocal||"—") + " • Cutoff: " + (L.cutoffAtLocal||"—");
    document.getElementById("owenCutoff").textContent = "Opens: " + (O.opensAtLocal||"—") + " • Cutoff: " + (O.cutoffAtLocal||"—");
  }

  function selectedOrderIds(){
    return Array.from(document.querySelectorAll("input[data-pick='1']:checked")).map(x=>x.value);
  }

  async function fetchOrders(){
    const q = document.getElementById("q").value.trim();
    const state = document.getElementById("state").value;
    const runKey = document.getElementById("runKey").value;
    const zone = document.getElementById("zone").value;
    const town = document.getElementById("town").value.trim();
    const unpaidFees = document.getElementById("unpaidFees").checked ? "1" : "";
    const hold = document.getElementById("holdOnly").checked ? "1" : "";
    const flag = document.getElementById("flag").value;

    const url = new URL(location.origin + api.list);
    if(q) url.searchParams.set("q", q);
    if(state) url.searchParams.set("state", state);
    if(runKey) url.searchParams.set("runKey", runKey);
    if(zone) url.searchParams.set("zone", zone);
    if(town) url.searchParams.set("town", town);
    if(unpaidFees) url.searchParams.set("unpaidFees", unpaidFees);
    if(hold) url.searchParams.set("hold", hold);
    if(flag) url.searchParams.set("flag", flag);
    url.searchParams.set("limit", "250");

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
      const payFees = o.payments?.fees?.status || "unpaid";
      const payGro = o.payments?.groceries?.status || "unpaid";
      const hold = !!o.hold;

      const flags = [];
      if (o.flags?.idRequired) flags.push("ID");
      if (o.flags?.prescription) flags.push("RX");
      if (o.flags?.alcohol) flags.push("ALC");
      if (o.flags?.bulky) flags.push("BULKY");
      if (o.flags?.newCustomerDepositRequired) flags.push("DEP");
      if (o.flags?.needsContact) flags.push("CALL");
      const flagText = flags.length ? flags.join(" ") : "—";

      tr.innerHTML = \`
        <td><input type="checkbox" data-pick="1" value="\${o.orderId}" style="width:18px;height:18px;"></td>

        <td>
          <div style="font-weight:1000;">\${o.orderId}</div>
          <div class="muted small">\${new Date(o.createdAt).toLocaleString()}</div>
        </td>

        <td>
          <div style="font-weight:900;">\${o.customer?.fullName || "—"}</div>
          <div class="muted small">\${o.customer?.phone || "—"} • \${o.customer?.email || "—"}</div>
        </td>

        <td>
          <span class="pill">\${o.runType}</span>
          <div class="muted small">\${o.runKey}</div>
        </td>

        <td>
          <div style="font-weight:900;">\${o.address?.town || "—"} (Zone \${o.address?.zone || "—"})</div>
          <div class="muted small">\${o.address?.streetAddress || "—"} \${o.address?.unit ? (" • " + o.address.unit) : ""} • \${o.address?.postalCode || ""}</div>
        </td>

        <td>
          <span class="pill">\${o.status?.state || "submitted"}</span>
          <div class="muted small">\${o.status?.note || ""}</div>
        </td>

        <td>\${money(fees)}</td>

        <td>
          <div class="muted small"><strong>Fees:</strong> \${payFees}</div>
          <div class="muted small"><strong>Groceries:</strong> \${payGro}</div>
          <div class="row" style="margin-top:6px;">
            <button class="btn" data-pay="\${o.orderId}">Edit</button>
          </div>
        </td>

        <td>
          <div class="muted small"><strong>Hold:</strong> \${hold ? "YES" : "no"}</div>
          <div class="muted small"><strong>Flags:</strong> \${flagText}</div>
          <div class="row" style="margin-top:6px;">
            <button class="btn" data-hold="\${o.orderId}">\${hold ? "Hold OFF" : "Hold ON"}</button>
            <button class="btn" data-flags="\${o.orderId}">Flags</button>
          </div>
        </td>

        <td class="row" style="gap:8px;">
          <button class="btn" data-status="confirmed" data-id="\${o.orderId}">Confirm</button>
          <button class="btn" data-status="shopping" data-id="\${o.orderId}">Shopping</button>
          <button class="btn" data-status="packed" data-id="\${o.orderId}">Packed</button>
          <button class="btn" data-status="out_for_delivery" data-id="\${o.orderId}">Out</button>
          <button class="btn" data-status="delivered" data-id="\${o.orderId}">Delivered</button>
          <button class="btn" data-status="issue" data-id="\${o.orderId}">Issue</button>
        </td>

        <td class="row" style="gap:8px;">
          <button class="btn" data-view="\${o.orderId}">View</button>
          <button class="btn" data-track="\${o.orderId}">Tracking link</button>
          <button class="btn" data-cancel="\${o.orderId}">Cancel</button>
          <button class="btn" data-del="\${o.orderId}">Delete</button>
        </td>
      \`;
      tbody.appendChild(tr);
    });

    // wire actions
    tbody.querySelectorAll("[data-view]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-view");
        const r = await fetch(api.one(id), { credentials:"include" });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "View failed");
        alert(JSON.stringify(d.order || {}, null, 2));
      });
    });

    tbody.querySelectorAll("[data-status]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-id");
        const state = btn.getAttribute("data-status");
        const note = prompt("Optional note for " + state + ":", "") || "";
        const r = await fetch(api.status(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ state, note }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Status failed");
        toast("Set " + id + " → " + state);
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

    tbody.querySelectorAll("[data-pay]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-pay");
        const feesStatus = prompt("Fees status (unpaid/paid):", "paid") || "";
        const groceriesStatus = prompt("Groceries status (unpaid/deposit_paid/paid):", "") || "";
        const note = prompt("Optional payment note:", "") || "";
        const r = await fetch(api.pay(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ feesStatus, groceriesStatus, note }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Payments update failed");
        toast("Payments updated " + id);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });

    tbody.querySelectorAll("[data-hold]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-hold");
        const rOne = await fetch(api.one(id), { credentials:"include" });
        const dOne = await rOne.json().catch(()=>({}));
        if(!rOne.ok || dOne.ok===false) return toast(dOne.error || "Fetch failed");
        const nowHold = !!(dOne.order?.hold);
        const r = await fetch(api.hold(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ hold: !nowHold }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Hold failed");
        toast("Hold " + (!nowHold ? "ON":"OFF") + " for " + id);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });

    tbody.querySelectorAll("[data-flags]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-flags");
        const rOne = await fetch(api.one(id), { credentials:"include" });
        const dOne = await rOne.json().catch(()=>({}));
        if(!rOne.ok || dOne.ok===false) return toast(dOne.error || "Fetch failed");
        const f = dOne.order?.flags || {};

        const idReq = confirm("Flag: ID required? (OK=yes, Cancel=no)");
        const rx = confirm("Flag: Prescription? (OK=yes, Cancel=no)");
        const alc = confirm("Flag: Alcohol? (OK=yes, Cancel=no)");
        const bulky = confirm("Flag: Bulky/heavy? (OK=yes, Cancel=no)");
        const dep = confirm("Flag: New customer deposit required? (OK=yes, Cancel=no)");
        const call = confirm("Flag: Needs contact? (OK=yes, Cancel=no)");

        const r = await fetch(api.flags(id), {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          credentials:"include",
          body: JSON.stringify({ flags: { idRequired:idReq, prescription:rx, alcohol:alc, bulky:bulky, newCustomerDepositRequired:dep, needsContact:call } }),
        });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Flags failed");
        toast("Flags updated " + id);
        fetchOrders().catch(e=>toast(String(e.message||e)));
      });
    });

    tbody.querySelectorAll("[data-track]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-track");
        const r = await fetch(api.tLink(id), { credentials:"include" });
        const d = await r.json().catch(()=>({}));
        if(!r.ok || d.ok===false) return toast(d.error || "Tracking link failed");
        try{
          await navigator.clipboard.writeText(d.url);
          toast("Tracking link copied ✅");
        } catch {
          alert(d.url);
        }
      });
    });
  }

  async function bulkStatus(){
    const ids = selectedOrderIds();
    const state = document.getElementById("bulkState").value;
    if(!ids.length) return toast("Select orders first");
    if(!state) return toast("Choose a bulk status");
    const note = prompt("Bulk status note:", "") || "";
    const r = await fetch(api.bulkStatus, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ orderIds: ids, state, note }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Bulk status failed");
    toast("Bulk updated: " + d.updated);
    fetchOrders().catch(e=>toast(String(e.message||e)));
  }

  async function bulkFeesPaid(){
    const ids = selectedOrderIds();
    if(!ids.length) return toast("Select orders first");
    const r = await fetch(api.bulkFeesPaid, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ orderIds: ids }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Bulk fees failed");
    toast("Fees marked paid: " + d.updated);
    fetchOrders().catch(e=>toast(String(e.message||e)));
  }

  async function bulkHold(hold){
    const ids = selectedOrderIds();
    if(!ids.length) return toast("Select orders first");
    const r = await fetch(api.bulkHold, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ orderIds: ids, hold }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Bulk hold failed");
    toast("Hold updated: " + d.updated);
    fetchOrders().catch(e=>toast(String(e.message||e)));
  }

  async function bulkCancel(){
    const ids = selectedOrderIds();
    if(!ids.length) return toast("Select orders first");
    const reason = prompt("Bulk cancel reason:", "Cancelled by admin (bulk)") || "";
    const r = await fetch(api.bulkCancel, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ orderIds: ids, reason }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Bulk cancel failed");
    toast("Cancelled: " + d.cancelled);
    fetchOrders().catch(e=>toast(String(e.message||e)));
  }

  async function bulkNotify(){
    const ids = selectedOrderIds();
    const tpl = document.getElementById("notifyTpl").value;
    if(!ids.length) return toast("Select orders first");
    if(!tpl) return toast("Choose an email template");
    const r = await fetch(api.notify, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ orderIds: ids, template: tpl }),
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Notify failed");
    toast("Emails sent: " + d.sent);
  }

  function openUrl(url){ window.location.href = url; }

  async function trackStart(runKey){
    if(!runKey) return toast("Missing runKey");
    const r = await fetch(api.tStart(runKey), { method:"POST", credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Tracking start failed");
    toast("Tracking started for " + runKey);
  }

  async function trackStop(runKey){
    if(!runKey) return toast("Missing runKey");
    const r = await fetch(api.tStop(runKey), { method:"POST", credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Tracking stop failed");
    toast("Tracking stopped for " + runKey);
  }

  // dashboard buttons
  document.getElementById("localExport").addEventListener("click", ()=> openUrl(api.exportCsv(runKeys.local)));
  document.getElementById("owenExport").addEventListener("click", ()=> openUrl(api.exportCsv(runKeys.owen)));
  document.getElementById("localPrint").addEventListener("click", ()=> openUrl(api.printPicks(runKeys.local)));
  document.getElementById("owenPrint").addEventListener("click", ()=> openUrl(api.printPicks(runKeys.owen)));
  document.getElementById("localTrackStart").addEventListener("click", ()=> trackStart(runKeys.local));
  document.getElementById("localTrackStop").addEventListener("click", ()=> trackStop(runKeys.local));
  document.getElementById("owenTrackStart").addEventListener("click", ()=> trackStart(runKeys.owen));
  document.getElementById("owenTrackStop").addEventListener("click", ()=> trackStop(runKeys.owen));

  document.getElementById("searchBtn").addEventListener("click", ()=>fetchOrders().catch(e=>toast(String(e.message||e))));
  document.getElementById("refreshBtn").addEventListener("click", ()=>{ fetchRuns().then(fetchOrders).catch(e=>toast(String(e.message||e))); });

  document.getElementById("bulkSetStatus").addEventListener("click", ()=> bulkStatus().catch(e=>toast(String(e.message||e))));
  document.getElementById("bulkFeesPaid").addEventListener("click", ()=> bulkFeesPaid().catch(e=>toast(String(e.message||e))));
  document.getElementById("bulkHoldOn").addEventListener("click", ()=> bulkHold(true).catch(e=>toast(String(e.message||e))));
  document.getElementById("bulkHoldOff").addEventListener("click", ()=> bulkHold(false).catch(e=>toast(String(e.message||e))));
  document.getElementById("bulkCancel").addEventListener("click", ()=> bulkCancel().catch(e=>toast(String(e.message||e))));
  document.getElementById("bulkNotify").addEventListener("click", ()=> bulkNotify().catch(e=>toast(String(e.message||e))));

  // clock line
  setInterval(()=>{
    const now = new Date();
    let line = "Local/OWEN cutoffs update every 60s • " + now.toLocaleString();
    document.getElementById("clockLine").textContent = line;
  }, 1000);

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