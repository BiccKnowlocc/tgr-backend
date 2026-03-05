// ======= server.js (FULL FILE) — TGR backend =======
// Google OAuth, profile onboarding, biweekly runs, estimator, orders, cancel tokens
// FULL ADMIN COMMAND CENTER + endpoints (search/view/status/payments/hold/flags/bulk/export/print/tracking/email)
// ADMIN Tracking Control mini-page: /admin/tracking-control (GPS broadcast from phone)
// MEMBER PORTAL (/member) restored + embedded live map (Mapbox) for active orders when tracking enabled
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
const POSTMARK_FROM_EMAIL =
  process.env.POSTMARK_FROM_EMAIL || "orders@tobermorygroceryrun.ca";
const POSTMARK_MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || "outbound";

const pmClient = POSTMARK_SERVER_TOKEN
  ? new postmark.ServerClient(POSTMARK_SERVER_TOKEN)
  : null;

// Square pay links (member portal quick buttons)
const SQUARE_PAY_GROCERIES_LINK =
  process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8";
const SQUARE_PAY_FEES_LINK =
  process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs";

// Membership purchase links (for your index.html)
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

// ======= CHANGED (DEDICATED FIELDS ADDED) =======
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

    // UPDATED: dedicated customer fields
    customer: {
      fullName: String,
      email: String,
      phone: String,
      altPhone: { type: String, default: "" },
      dob: { type: String, default: "" }, // YYYY-MM-DD
    },

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

    // NEW: dedicated add-ons
    addOns: {
      prescription: {
        requested: { type: Boolean, default: false },
        pharmacyName: { type: String, default: "" },
        notes: { type: String, default: "" },
      },
      liquor: {
        requested: { type: Boolean, default: false },
        storeName: { type: String, default: "" },
        notes: { type: String, default: "" },
        idRequired: { type: Boolean, default: true },
      },
      printing: {
        requested: { type: Boolean, default: false },
        pages: { type: Number, default: 0 },
        notes: { type: String, default: "" },
      },
      fastFood: {
        requested: { type: Boolean, default: false },
        restaurant: { type: String, default: "" },
        orderDetails: { type: String, default: "" },
      },
      parcel: {
        requested: { type: Boolean, default: false },
        carrier: { type: String, default: "" },
        details: { type: String, default: "" },
      },
      bulky: {
        requested: { type: Boolean, default: false },
        details: { type: String, default: "" },
      },
      ride: {
        requested: { type: Boolean, default: false },
        pickupAddress: { type: String, default: "" },
        preferredWindow: { type: String, default: "" },
        notes: { type: String, default: "" },
      },
      generalNotes: { type: String, default: "" },
    },

    // NEW: dedicated delivery meta
    deliveryMeta: {
      gateCode: { type: String, default: "" },
      buildingAccessNotes: { type: String, default: "" },
      parkingNotes: { type: String, default: "" },
      budgetCap: { type: Number, default: 0 },
      receiptPreference: { type: String, default: "" },
      photoProofOk: { type: Boolean, default: false },
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
    if (!t.enabled) return res.json({ ok: true, enabled: false, hasFix: false });

    if (!t.lastAt || typeof t.lastLat !== "number" || typeof t.lastLng !== "number") {
      return res.json({ ok: true, enabled: true, hasFix: false });
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
  res.json({
    ok: true,
    mapboxPublicToken: MAPBOX_PUBLIC_TOKEN || "",
    squareMembershipLinks: {
      standard: SQUARE_LINK_STANDARD,
      route: SQUARE_LINK_ROUTE,
      access: SQUARE_LINK_ACCESS,
      accesspro: SQUARE_LINK_ACCESSPRO,
    }
  });
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

    // ======= CHANGED (DEDICATED FIELDS PARSING) =======
    const dob = String(b.dob || "").trim(); // YYYY-MM-DD
    const altPhone = String(b.altPhone || "").trim();

    const addPrescription = yn(b.addon_prescription);
    const addLiquor = yn(b.addon_liquor);
    const addPrinting = yn(b.addon_printing);
    const addFastFood = yn(b.addon_fastfood);
    const addParcel = yn(b.addon_parcel);
    const addBulky = yn(b.addon_bulky);
    const addRide = yn(b.addon_ride);

    const prescriptionPharmacy = String(b.prescriptionPharmacy || "").trim();
    const prescriptionNotes = String(b.prescriptionNotes || "").trim();

    const liquorStore = String(b.liquorStore || "").trim();
    const liquorNotes = String(b.liquorNotes || "").trim();

    const printingNotes = String(b.printingNotes || "").trim();

    const fastFoodRestaurant = String(b.fastFoodRestaurant || "").trim();
    const fastFoodOrder = String(b.fastFoodOrder || "").trim();

    const parcelCarrier = String(b.parcelCarrier || "").trim();
    const parcelDetails = String(b.parcelDetails || "").trim();

    const bulkyDetails = String(b.bulkyDetails || "").trim();

    const ridePickup = String(b.ridePickup || "").trim();
    const rideWindow = String(b.rideWindow || "").trim();
    const rideNotes = String(b.rideNotes || "").trim();

    const generalNotes = String(b.optionalNotes || "").trim();

    const gateCode = String(b.gateCode || "").trim();
    const buildingAccessNotes = String(b.buildingAccessNotes || "").trim();
    const parkingNotes = String(b.parkingNotes || "").trim();
    const budgetCap = Math.max(0, Number(b.budgetCap || 0));
    const receiptPreference = String(b.receiptPreference || "").trim();
    const photoProofOk = yn(b.photoProofOk);

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

      // UPDATED: populate flags from dedicated add-ons (keeps your admin filters useful)
      flags: {
        prescription: addPrescription,
        alcohol: addLiquor,
        bulky: addBulky,
        idRequired: addLiquor,
      },

      customer: {
        fullName,
        email: String(user.email || "").trim().toLowerCase(),
        phone,
        altPhone,
        dob,
      },

      address: { town, streetAddress, unit, postalCode, zone },
      stores: { primary: primaryStore, extra: extraStores },
      preferences: { dropoffPref, subsPref, contactPref, contactAuth: true },

      addOns: {
        prescription: { requested: addPrescription, pharmacyName: prescriptionPharmacy, notes: prescriptionNotes },
        liquor: { requested: addLiquor, storeName: liquorStore, notes: liquorNotes, idRequired: true },
        printing: { requested: addPrinting, pages: Math.max(0, Number(b.printPages || 0)), notes: printingNotes },
        fastFood: { requested: addFastFood, restaurant: fastFoodRestaurant, orderDetails: fastFoodOrder },
        parcel: { requested: addParcel, carrier: parcelCarrier, details: parcelDetails },
        bulky: { requested: addBulky, details: bulkyDetails },
        ride: { requested: addRide, pickupAddress: ridePickup, preferredWindow: rideWindow, notes: rideNotes },
        generalNotes,
      },

      deliveryMeta: {
        gateCode,
        buildingAccessNotes,
        parkingNotes,
        budgetCap,
        receiptPreference,
        photoProofOk,
      },

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
        <p style="margin:0;">Member Portal: <a href="${escapeHtml("https://api.tobermorygroceryrun.ca/member")}">${escapeHtml("https://api.tobermorygroceryrun.ca/member")}</a></p>
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
// MEMBER PORTAL (UPGRADED: embedded map)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const name = String(req.user?.name || "").trim();

    const orders = await Order.find({ "customer.email": email })
      .sort({ createdAt: -1 })
      .limit(80)
      .lean();

    const runKeys = Array.from(new Set(orders.map(o => o.runKey).filter(Boolean)));
    const runs = await Run.find({ runKey: { $in: runKeys } }).lean();
    const runByKey = new Map(runs.map(r => [r.runKey, r]));

    const now = nowTz();

    // Build a list of trackable orders with tokens embedded
    const trackables = [];
    for (const o of orders) {
      const status = o.status?.state || "submitted";
      if (!ACTIVE_STATES.has(status)) continue;
      const run = runByKey.get(o.runKey);
      if (!run?.runKey || !run?.cutoffAt) continue;
      const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf();
      const tkn = signTrackingToken(o.orderId, run.runKey, expMs);
      trackables.push({
        orderId: o.orderId,
        runKey: run.runKey,
        token: tkn,
        status,
      });
    }

    const rows = orders.map(o => {
      const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
      const status = o.status?.state || "submitted";
      const run = runByKey.get(o.runKey);
      const cutoffAt = run?.cutoffAt ? dayjs(run.cutoffAt).tz(TZ) : null;
      const cancelOpen = cutoffAt ? now.isBefore(cutoffAt) : false;

      let cancelHtml = `<span class="muted">—</span>`;
      if (ACTIVE_STATES.has(status) && cancelOpen) {
        const token = signCancelToken(o.orderId, cutoffAt.toDate().getTime());
        cancelHtml = `<button class="btn" data-cancel="${escapeHtml(o.orderId)}" data-token="${escapeHtml(token)}">Cancel</button>`;
      } else if (status === "cancelled") {
        cancelHtml = `<span class="pill">Cancelled</span>`;
      } else if (!cancelOpen && ACTIVE_STATES.has(status)) {
        cancelHtml = `<span class="muted">Past cutoff</span>`;
      }

      let trackHtml = `<span class="muted">—</span>`;
      if (ACTIVE_STATES.has(status) && run?.runKey && run?.cutoffAt) {
        const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf();
        const tkn = signTrackingToken(o.orderId, run.runKey, expMs);
        const link = `https://api.tobermorygroceryrun.ca/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(tkn)}&orderId=${encodeURIComponent(o.orderId)}`;
        trackHtml = `
          <button class="btn" data-track-run="${escapeHtml(run.runKey)}" data-track-token="${escapeHtml(tkn)}" data-track-order="${escapeHtml(o.orderId)}">Track on map</button>
          <button class="btn" data-copy="${escapeHtml(link)}">Copy link</button>
        `;
      }

      const addr =
        `${o.address?.streetAddress || ""}${o.address?.unit ? " " + o.address.unit : ""}, ` +
        `${o.address?.town || ""}, ON ${o.address?.postalCode || ""}`.trim();

      return `
        <tr>
          <td><div style="font-weight:1000;">${escapeHtml(o.orderId)}</div><div class="muted" style="font-size:12px;">${escapeHtml(fmtLocal(o.createdAt))}</div></td>
          <td><div style="font-weight:900;">${escapeHtml(addr)}</div><div class="muted" style="font-size:12px;">Zone ${escapeHtml(o.address?.zone || "")}</div></td>
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
  .wrap{max-width:1250px;margin:0 auto;padding:16px;}
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
  .grid{display:grid;grid-template-columns: 1fr 1fr; gap:12px;}
  @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} }
  #mapWrap{display:none;}
  #map{height: 420px; border-radius: 14px; border:1px solid rgba(255,255,255,.14); overflow:hidden;}
  .small{font-size:13px;}
  .warn{border:1px solid rgba(227,52,47,.45);background:rgba(227,52,47,.12);border-radius:12px;padding:10px 12px;}
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

    <div class="grid" id="mapWrap">
      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;font-size:18px;">Live Tracking Map</div>
        <div class="muted small" id="mapSub">Select an order to track. Tracking only works when enabled for the run.</div>
        <div class="hr"></div>
        <div id="map"></div>
        <div class="hr"></div>
        <div class="row">
          <span class="pill" id="mapStatus">—</span>
          <span class="pill" id="mapLast">Last: —</span>
          <button class="btn" id="stopMap">Stop</button>
        </div>
        <div class="muted small" id="mapErr" style="margin-top:10px;"></div>
      </div>

      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;font-size:18px;">Tracking controls</div>
        <div class="muted small">Only your active orders can track. If tracking is disabled, you’ll see “Tracking off”.</div>
        <div class="hr"></div>
        <div class="warn">
          <div style="font-weight:1000;">Tip</div>
          <div class="muted small">If your map is blank, the driver hasn’t started tracking or hasn’t sent a GPS fix yet.</div>
        </div>
      </div>
    </div>

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
  const TRACKABLES = ${JSON.stringify(trackables)};
  let MAPBOX_TOKEN = "";
  let map = null;
  let marker = null;
  let pollTimer = null;
  let activeTrack = null;

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

  document.querySelectorAll("[data-copy]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      const url = btn.getAttribute("data-copy");
      if (await copy(url)) toast("Link copied ✅");
      else toast("Copy failed");
    });
  });

  document.querySelectorAll("[data-track-run]").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      const runKey = btn.getAttribute("data-track-run");
      const token = btn.getAttribute("data-track-token");
      const orderId = btn.getAttribute("data-track-order");
      startMapTracking({ runKey, token, orderId });
    });
  });

  document.getElementById("stopMap").addEventListener("click", ()=> stopMapTracking());

  function qs(){
    const u = new URL(location.href);
    return {
      runKey: u.searchParams.get("trackRunKey") || "",
      token: u.searchParams.get("token") || "",
      orderId: u.searchParams.get("orderId") || "",
    };
  }

  async function loadConfig(){
    const r = await fetch("/api/public/config");
    const d = await r.json().catch(()=>({}));
    if(r.ok && d.ok) MAPBOX_TOKEN = d.mapboxPublicToken || "";
  }

  function setMapWrap(show){
    document.getElementById("mapWrap").style.display = show ? "grid" : "none";
  }

  function setStatus(text){ document.getElementById("mapStatus").textContent = text; }
  function setLast(text){ document.getElementById("mapLast").textContent = text; }
  function setErr(text){ document.getElementById("mapErr").textContent = text || ""; }

  function loadMapboxLib(){
    return new Promise((resolve, reject)=>{
      if (window.mapboxgl) return resolve();
      const css = document.createElement("link");
      css.rel = "stylesheet";
      css.href = "https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.css";
      document.head.appendChild(css);

      const s = document.createElement("script");
      s.src = "https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.js";
      s.onload = ()=> resolve();
      s.onerror = ()=> reject(new Error("Mapbox failed to load"));
      document.head.appendChild(s);
    });
  }

  async function ensureMap(){
    if (map) return;
    if (!MAPBOX_TOKEN) throw new Error("Mapbox token missing on server");
    await loadMapboxLib();

    mapboxgl.accessToken = MAPBOX_TOKEN;
    map = new mapboxgl.Map({
      container: "map",
      style: "mapbox://styles/mapbox/dark-v11",
      center: [-81.7, 45.25],
      zoom: 9,
    });
    marker = new mapboxgl.Marker({ color: "#ff4a44" }).setLngLat([-81.7, 45.25]).addTo(map);
  }

  function stopMapTracking(){
    activeTrack = null;
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    setStatus("—");
    setLast("Last: —");
    setErr("");
    toast("Tracking stopped");
  }

  async function pollOnce(){
    if (!activeTrack) return;
    const { runKey, token } = activeTrack;
    try{
      const r = await fetch("/api/public/tracking/" + encodeURIComponent(runKey) + "?token=" + encodeURIComponent(token));
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false){
        setStatus("Error");
        setErr(d.error || "Tracking error");
        return;
      }

      if (!d.enabled){
        setStatus("Tracking off");
        setErr("Tracking is not enabled for this run yet.");
        return;
      }
      if (!d.hasFix){
        setStatus("Waiting for GPS");
        setErr("No GPS fix yet. Try again in a moment.");
        return;
      }

      const lat = d.last.lat;
      const lng = d.last.lng;
      const at = d.last.at ? new Date(d.last.at).toLocaleString() : "—";

      setStatus("Live ✅");
      setLast("Last: " + at);
      setErr("");

      marker.setLngLat([lng, lat]);
      map.easeTo({ center: [lng, lat], zoom: 12, duration: 900 });
    } catch (e){
      setStatus("Error");
      setErr(String(e.message || e));
    }
  }

  async function startMapTracking(t){
    activeTrack = t;
    setMapWrap(true);
    setStatus("Loading…");
    setLast("Last: —");
    setErr("");

    document.getElementById("mapSub").textContent =
      "Tracking " + (t.orderId || "") + " • " + (t.runKey || "");

    try{
      await ensureMap();
      await pollOnce();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(pollOnce, 2500);
      toast("Map tracking started ✅");
    } catch (e){
      setStatus("Error");
      setErr(String(e.message || e));
    }
  }

  (async function boot(){
    await loadConfig();

    const p = qs();
    if (p.runKey && p.token) {
      startMapTracking({ runKey: p.runKey, token: p.token, orderId: p.orderId || "" });
      return;
    }

    setMapWrap(false);
  })();
</script>

</body>
</html>`);
  } catch (e) {
    res.status(500).send("Member portal error: " + String(e));
  }
});

// =========================
// ADMIN API ENDPOINTS + PAGES
// =========================
function adminBy(req) {
  return String(req.user?.email || "admin").toLowerCase();
}

function buildOrderFilterFromQuery(qs) {
  const q = String(qs.q || "").trim();
  const state = String(qs.state || "").trim();
  const runKey = String(qs.runKey || "").trim();
  const zone = String(qs.zone || "").trim();
  const town = String(qs.town || "").trim();
  const unpaidFees = String(qs.unpaidFees || "").trim() === "1";
  const hold = String(qs.hold || "").trim() === "1";
  const flag = String(qs.flag || "").trim();

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

    await order.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/payments", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();

    const feesStatus = String(req.body?.feesStatus || "").trim();
    const groceriesStatus = String(req.body?.groceriesStatus || "").trim();
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

    await order.save();
    res.json({ ok: true });
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

// Tracking admin controls
app.post("/api/admin/tracking/:runKey/start", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const by = adminBy(req);
    await ensureTrackingDoc(runKey);
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

// Update live GPS from phone (admin session cookie required)
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

    const url = `https://api.tobermorygroceryrun.ca/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(token)}&orderId=${encodeURIComponent(o.orderId)}`;
    res.json({ ok: true, url });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// ADMIN COMMAND CENTER PAGE (RESTORED)
// =========================
app.get("/admin", requireLogin, requireAdmin, async (_req, res) => {
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
  .wrap{max-width:1400px;margin:0 auto;padding:16px;}
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
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
  input,select,textarea{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid rgba(255,255,255,.18);
    background:rgba(0,0,0,.22);
    color:#fff;
    font-size:15px;
    outline:none;
  }
  textarea{min-height:90px;resize:vertical;}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;}
  th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;}
  .grid{display:grid;grid-template-columns: 1.1fr .9fr; gap:12px;}
  @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} }
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
  .toast.show{display:block;}
  .modalBack{
    position:fixed; inset:0; background:rgba(0,0,0,.55);
    display:none; align-items:center; justify-content:center; padding:16px;
  }
  .modal{
    width:min(980px, 100%); max-height: 92vh; overflow:auto;
    border:1px solid rgba(255,255,255,.16); background:#0b0b0b;
    border-radius:16px; padding:14px;
  }
  .k{font-size:12px;color:rgba(255,255,255,.7);text-transform:uppercase;letter-spacing:.08em;}
  .v{font-weight:900;}
  .two{display:grid;grid-template-columns: 1fr 1fr; gap:10px;}
  @media(max-width:800px){.two{grid-template-columns:1fr;}}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div>
        <div style="font-weight:1000;font-size:22px;">Admin Command Center</div>
        <div class="muted">Search, view, status updates, payments, tracking links, export.</div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn" href="/admin/tracking-control">Tracking Control</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>

    <div class="hr"></div>

    <div class="grid">
      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;">Search / Filters</div>
        <div class="hr"></div>

        <div class="row">
          <div style="flex: 2 1 320px;">
            <label class="muted" style="font-weight:900;">Search</label>
            <input id="q" placeholder="orderId, name, email, phone, address" />
          </div>
          <div style="flex: 1 1 180px;">
            <label class="muted" style="font-weight:900;">State</label>
            <select id="state">
              <option value="">Any</option>
              <option>submitted</option>
              <option>confirmed</option>
              <option>shopping</option>
              <option>packed</option>
              <option>out_for_delivery</option>
              <option>delivered</option>
              <option>issue</option>
              <option>cancelled</option>
            </select>
          </div>
          <div style="flex: 1 1 180px;">
            <label class="muted" style="font-weight:900;">Run Key</label>
            <input id="runKey" placeholder="YYYY-MM-DD-local" />
          </div>
        </div>

        <div class="row">
          <div style="flex: 1 1 160px;">
            <label class="muted" style="font-weight:900;">Zone</label>
            <select id="zone">
              <option value="">Any</option>
              <option>A</option><option>B</option><option>C</option><option>D</option>
            </select>
          </div>
          <div style="flex: 1 1 220px;">
            <label class="muted" style="font-weight:900;">Town</label>
            <input id="town" placeholder="e.g., Tobermory" />
          </div>
          <div style="flex: 1 1 220px;">
            <label class="muted" style="font-weight:900;">Flag</label>
            <select id="flag">
              <option value="">Any</option>
              <option value="idRequired">idRequired</option>
              <option value="prescription">prescription</option>
              <option value="alcohol">alcohol</option>
              <option value="bulky">bulky</option>
              <option value="needsContact">needsContact</option>
              <option value="newCustomerDepositRequired">newCustomerDepositRequired</option>
            </select>
          </div>
        </div>

        <div class="row">
          <label class="row" style="gap:8px;">
            <input id="unpaidFees" type="checkbox" style="width:18px;height:18px;">
            <span class="muted" style="font-weight:900;">Unpaid fees only</span>
          </label>
          <label class="row" style="gap:8px;">
            <input id="hold" type="checkbox" style="width:18px;height:18px;">
            <span class="muted" style="font-weight:900;">Hold only</span>
          </label>
        </div>

        <div class="row" style="margin-top:8px;">
          <button class="btn primary" id="searchBtn">Search</button>
          <button class="btn" id="refreshBtn">Refresh</button>
          <button class="btn ghost" id="clearBtn">Clear</button>
          <span class="pill" id="countPill">—</span>
        </div>
      </div>

      <div class="card" style="box-shadow:none;">
        <div style="font-weight:1000;">Quick Tools</div>
        <div class="hr"></div>

        <div class="muted">Export active deliveries for Routific by runKey:</div>
        <div class="row" style="margin-top:10px;">
          <div style="flex:1 1 260px;">
            <input id="exportRunKey" placeholder="YYYY-MM-DD-local" />
          </div>
          <button class="btn" id="exportBtn">Download CSV</button>
        </div>

        <div class="hr"></div>

        <div class="muted">Tip: open an order to update state, payments, or copy tracking link.</div>
      </div>
    </div>

    <div class="hr"></div>

    <div style="overflow:auto;">
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Customer</th>
            <th>Address</th>
            <th>Run</th>
            <th>Status</th>
            <th>Fees</th>
            <th>Flags</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="rows">
          <tr><td colspan="8" class="muted">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="modalBack" id="modalBack" style="position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:16px;">
  <div class="modal" style="width:min(980px,100%);max-height:92vh;overflow:auto;border:1px solid rgba(255,255,255,.16);background:#0b0b0b;border-radius:16px;padding:14px;">
    <div class="row" style="justify-content:space-between;">
      <div style="font-weight:1000;font-size:20px;">Order Details</div>
      <button class="btn ghost" id="closeModal">Close</button>
    </div>
    <div class="hr"></div>

    <div class="two" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div class="card" style="box-shadow:none;">
        <div class="k">Order ID</div><div class="v" id="m_orderId">—</div>
        <div class="hr"></div>
        <div class="k">Customer</div><div class="v" id="m_customer">—</div>
        <div class="k">Phone</div><div class="v" id="m_phone">—</div>
        <div class="k">Email</div><div class="v" id="m_email">—</div>
        <div class="hr"></div>
        <div class="k">Address</div><div class="v" id="m_addr">—</div>
        <div class="k">Zone</div><div class="v" id="m_zone">—</div>
        <div class="k">Run</div><div class="v" id="m_run">—</div>
      </div>

      <div class="card" style="box-shadow:none;">
        <div class="k">Fees total</div><div class="v" id="m_fees">—</div>

        <label class="muted" style="font-weight:900;">Status state</label>
        <select id="m_state">
          <option>submitted</option>
          <option>confirmed</option>
          <option>shopping</option>
          <option>packed</option>
          <option>out_for_delivery</option>
          <option>delivered</option>
          <option>issue</option>
          <option>cancelled</option>
        </select>

        <label class="muted" style="font-weight:900;">Status note (optional)</label>
        <input id="m_stateNote" placeholder="Short note" />

        <div class="row" style="margin-top:10px;">
          <button class="btn primary" id="m_saveState">Save status</button>
          <button class="btn" id="m_trackingLink">Copy tracking link</button>
        </div>

        <div class="hr"></div>

        <div class="row">
          <div style="flex:1 1 200px;">
            <label class="muted" style="font-weight:900;">Fees status</label>
            <select id="m_feesStatus">
              <option value="">(no change)</option>
              <option value="unpaid">unpaid</option>
              <option value="paid">paid</option>
            </select>
          </div>
          <div style="flex:1 1 200px;">
            <label class="muted" style="font-weight:900;">Groceries status</label>
            <select id="m_groceriesStatus">
              <option value="">(no change)</option>
              <option value="unpaid">unpaid</option>
              <option value="deposit_paid">deposit_paid</option>
              <option value="paid">paid</option>
            </select>
          </div>
        </div>

        <label class="muted" style="font-weight:900;">Payment note (optional)</label>
        <input id="m_payNote" placeholder="e.g., paid cash, e-transfer, Square receipt #" />

        <div class="row" style="margin-top:10px;">
          <button class="btn" id="m_savePay">Save payments</button>
          <button class="btn" id="m_cancelAdmin">Cancel order (admin)</button>
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="card" style="box-shadow:none;">
      <div style="font-weight:1000;">Grocery list</div>
      <div class="hr"></div>
      <pre id="m_list" style="white-space:pre-wrap; margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;"></pre>
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

  const qs = (k)=> document.getElementById(k);
  const rowsEl = qs("rows");
  const countPill = qs("countPill");

  let modalOrder = null;

  function buildQuery(){
    const p = new URLSearchParams();
    const q = qs("q").value.trim();
    const state = qs("state").value.trim();
    const runKey = qs("runKey").value.trim();
    const zone = qs("zone").value.trim();
    const town = qs("town").value.trim();
    const flag = qs("flag").value.trim();
    const unpaidFees = qs("unpaidFees").checked ? "1" : "";
    const hold = qs("hold").checked ? "1" : "";

    if(q) p.set("q", q);
    if(state) p.set("state", state);
    if(runKey) p.set("runKey", runKey);
    if(zone) p.set("zone", zone);
    if(town) p.set("town", town);
    if(flag) p.set("flag", flag);
    if(unpaidFees) p.set("unpaidFees", unpaidFees);
    if(hold) p.set("hold", hold);
    p.set("limit","200");
    return p.toString();
  }

  function esc(s){
    return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
  }

  function money(n){
    const x = Number(n||0);
    return x.toFixed(2);
  }

  function render(items){
    const list = items || [];
    countPill.textContent = "Results: " + list.length;

    if(!list.length){
      rowsEl.innerHTML = '<tr><td colspan="8" class="muted">No results.</td></tr>';
      return;
    }

    rowsEl.innerHTML = list.map(o=>{
      const id = esc(o.orderId);
      const cust = esc(o.customer?.fullName || "");
      const phone = esc(o.customer?.phone || "");
      const email = esc(o.customer?.email || "");
      const addr = esc((o.address?.streetAddress||"") + (o.address?.unit ? (" " + o.address.unit) : "") + ", " + (o.address?.town||"") + " " + (o.address?.postalCode||""));
      const run = esc(o.runKey || "");
      const rt = esc(o.runType || "");
      const st = esc(o.status?.state || "");
      const fees = money(o.pricingSnapshot?.totalFees || 0);
      const flags = [];
      const f = o.flags || {};
      Object.keys(f).forEach(k=>{ if (f[k] === true) flags.push(k); });
      const flagTxt = esc(flags.join(", "));

      return \`
        <tr>
          <td><div style="font-weight:1000;">\${id}</div><div class="muted" style="font-size:12px;">\${email}</div></td>
          <td><div style="font-weight:900;">\${cust}</div><div class="muted" style="font-size:12px;">\${phone}</div></td>
          <td>\${addr}</td>
          <td><span class="pill">\${rt}</span><div class="muted" style="font-size:12px;margin-top:4px;">\${run}</div></td>
          <td><span class="pill">\${st}</span></td>
          <td>$\${fees}</td>
          <td><div class="muted" style="font-size:12px;">\${flagTxt}</div></td>
          <td><button class="btn" data-open="\${id}">Open</button></td>
        </tr>
      \`;
    }).join("");

    document.querySelectorAll("[data-open]").forEach(btn=>{
      btn.addEventListener("click", ()=> openOrder(btn.getAttribute("data-open")));
    });
  }

  async function search(){
    rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Loading…</td></tr>';
    try{
      const r = await fetch("/api/admin/orders?" + buildQuery(), { credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Load failed");
      render(d.items || []);
    } catch(e){
      rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Error: ' + esc(e.message||e) + '</td></tr>';
    }
  }

  function openModal(show){
    qs("modalBack").style.display = show ? "flex" : "none";
  }

  async function openOrder(orderId){
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(orderId), { credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Order load failed");
      modalOrder = d.order;

      qs("m_orderId").textContent = modalOrder.orderId || "—";
      qs("m_customer").textContent = modalOrder.customer?.fullName || "—";
      qs("m_phone").textContent = modalOrder.customer?.phone || "—";
      qs("m_email").textContent = modalOrder.customer?.email || "—";
      qs("m_addr").textContent = (modalOrder.address?.streetAddress||"") + (modalOrder.address?.unit ? (" " + modalOrder.address.unit) : "");
      qs("m_zone").textContent = modalOrder.address?.zone || "—";
      qs("m_run").textContent = (modalOrder.runKey||"") + " (" + (modalOrder.runType||"") + ")";
      qs("m_fees").textContent = "$" + money(modalOrder.pricingSnapshot?.totalFees || 0);

      qs("m_state").value = (modalOrder.status?.state || "submitted");
      qs("m_stateNote").value = (modalOrder.status?.note || "");
      qs("m_list").textContent = modalOrder.list?.groceryListText || "";

      qs("m_feesStatus").value = "";
      qs("m_groceriesStatus").value = "";
      qs("m_payNote").value = "";

      openModal(true);
    } catch(e){
      toast(String(e.message||e));
    }
  }

  async function saveStatus(){
    if(!modalOrder?.orderId) return;
    const state = qs("m_state").value;
    const note = qs("m_stateNote").value.trim();
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/status", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        credentials:"include",
        body: JSON.stringify({ state, note })
      });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Save failed");
      toast("Status saved ✅");
      await search();
    } catch(e){
      toast(String(e.message||e));
    }
  }

  async function savePayments(){
    if(!modalOrder?.orderId) return;
    const feesStatus = qs("m_feesStatus").value;
    const groceriesStatus = qs("m_groceriesStatus").value;
    const note = qs("m_payNote").value.trim();
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/payments", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        credentials:"include",
        body: JSON.stringify({ feesStatus, groceriesStatus, note })
      });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Save failed");
      toast("Payments saved ✅");
      await openOrder(modalOrder.orderId);
      await search();
    } catch(e){
      toast(String(e.message||e));
    }
  }

  async function cancelAdmin(){
    if(!modalOrder?.orderId) return;
    const ok = confirm("Cancel this order as admin?");
    if(!ok) return;
    const reason = prompt("Reason (optional):", "Cancelled by admin") || "Cancelled by admin";
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/cancel", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        credentials:"include",
        body: JSON.stringify({ reason })
      });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Cancel failed");
      toast("Order cancelled ✅");
      openModal(false);
      await search();
    } catch(e){
      toast(String(e.message||e));
    }
  }

  async function copyTrackingLink(){
    if(!modalOrder?.orderId) return;
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/tracking-link", { credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Link failed");
      await navigator.clipboard.writeText(d.url || "");
      toast("Tracking link copied ✅");
    } catch(e){
      toast(String(e.message||e));
    }
  }

  function clearFilters(){
    qs("q").value=""; qs("state").value=""; qs("runKey").value="";
    qs("zone").value=""; qs("town").value=""; qs("flag").value="";
    qs("unpaidFees").checked=false; qs("hold").checked=false;
  }

  qs("searchBtn").addEventListener("click", search);
  qs("refreshBtn").addEventListener("click", search);
  qs("clearBtn").addEventListener("click", ()=>{ clearFilters(); search(); });

  qs("exportBtn").addEventListener("click", ()=>{
    const rk = qs("exportRunKey").value.trim();
    if(!rk) return toast("Enter runKey to export");
    window.location.href = "/api/admin/routific/export-csv?runKey=" + encodeURIComponent(rk);
  });

  qs("closeModal").addEventListener("click", ()=> openModal(false));
  qs("modalBack").addEventListener("click", (e)=>{ if(e.target.id==="modalBack") openModal(false); });

  qs("m_saveState").addEventListener("click", saveStatus);
  qs("m_savePay").addEventListener("click", savePayments);
  qs("m_cancelAdmin").addEventListener("click", cancelAdmin);
  qs("m_trackingLink").addEventListener("click", copyTrackingLink);

  search();
</script>
</body>
</html>`);
});

// =========================
// ADMIN COMMAND CENTER PAGE (kept minimal here)
// =========================
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
// ADMIN: Tracking Control mini-page (NEW)
// =========================
app.get("/admin/tracking-control", requireLogin, requireAdmin, async (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Tracking Control</title>
<style>
  :root{
    --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.75);
    --red:#e3342f; --red2:#ff4a44;
    --radius:14px;
  }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:900px;margin:0 auto;padding:16px;}
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
  select,input{
    width:100%;
    padding:12px 12px;
    border-radius:12px;
    border:1px solid rgba(255,255,255,.18);
    background:rgba(0,0,0,.25);
    color:#fff;
    font-size:16px;
  }
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
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
        <div style="font-weight:1000;font-size:22px;">Tracking Control</div>
        <div class="muted">Use this page on your phone while signed into admin.</div>
      </div>
      <div class="row">
        <a class="btn ghost" href="/admin">Admin</a>
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>
    <div class="hr"></div>

    <div class="row">
      <div style="flex:1 1 380px;">
        <label class="muted" style="font-weight:900;">Select run</label>
        <select id="runSel">
          <option value="">Loading…</option>
        </select>
        <div class="muted" id="runInfo" style="margin-top:8px;font-size:13px;"></div>
      </div>

      <div style="flex:1 1 240px;">
        <label class="muted" style="font-weight:900;">GPS send interval (ms)</label>
        <input id="interval" type="number" min="500" step="100" value="1500"/>
      </div>
    </div>

    <div class="hr"></div>

    <div class="row">
      <button class="btn" id="enableBtn">Start tracking (enable run)</button>
      <button class="btn" id="disableBtn">Stop tracking (disable run)</button>
      <span class="pill" id="enabledState">—</span>
    </div>

    <div class="hr"></div>

    <div class="row">
      <button class="btn primary" id="startGps">Start GPS broadcast</button>
      <button class="btn" id="stopGps">Stop GPS broadcast</button>
      <span class="pill" id="gpsState">GPS: idle</span>
    </div>

    <div class="muted" id="lastSend" style="margin-top:10px;font-size:13px;">Last send: —</div>
    <div class="muted" id="err" style="margin-top:6px;font-size:13px;"></div>
  </div>
</div>

<script>
  const toast = (msg)=>{
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(()=>el.classList.remove("show"), 3500);
  };

  const runSel = document.getElementById("runSel");
  const runInfo = document.getElementById("runInfo");
  const enabledState = document.getElementById("enabledState");
  const gpsState = document.getElementById("gpsState");
  const lastSend = document.getElementById("lastSend");
  const err = document.getElementById("err");
  const intervalEl = document.getElementById("interval");

  let runs = null;
  let watchId = null;
  let lastPostAt = 0;

  async function loadRuns(){
    const r = await fetch("/api/runs/active", { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Runs unavailable");
    runs = d.runs || null;

    runSel.innerHTML = '<option value="">Select…</option>';
    const L = runs.local;
    const O = runs.owen;
    if (L?.runKey){
      const o = document.createElement("option");
      o.value = L.runKey; o.textContent = "Local: " + L.runKey;
      runSel.appendChild(o);
    }
    if (O?.runKey){
      const o = document.createElement("option");
      o.value = O.runKey; o.textContent = "Owen: " + O.runKey;
      runSel.appendChild(o);
    }
  }

  function getRunByKey(k){
    if (!runs) return null;
    if (runs.local?.runKey === k) return runs.local;
    if (runs.owen?.runKey === k) return runs.owen;
    return null;
  }

  function updateRunInfo(){
    const k = runSel.value;
    const r = getRunByKey(k);
    if(!r){ runInfo.textContent = ""; enabledState.textContent = "—"; return; }
    runInfo.textContent = "Opens: " + r.opensAtLocal + " • Cutoff: " + r.cutoffAtLocal + " • Slots: " + r.slotsRemaining;
    enabledState.textContent = r.isOpen ? "Orders open" : "Orders closed";
  }

  runSel.addEventListener("change", updateRunInfo);

  async function enableTracking(){
    const k = runSel.value;
    if(!k) return toast("Select a runKey");
    const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/start", { method:"POST", credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Enable failed");
    toast("Tracking enabled for " + k);
  }

  async function disableTracking(){
    const k = runSel.value;
    if(!k) return toast("Select a runKey");
    const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/stop", { method:"POST", credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Disable failed");
    toast("Tracking disabled for " + k);
  }

  async function postFix(pos){
    const k = runSel.value;
    if(!k) return;

    const ms = Math.max(500, Number(intervalEl.value || 1500));
    const now = Date.now();
    if ((now - lastPostAt) < ms) return;
    lastPostAt = now;

    const c = pos.coords || {};
    const body = {
      lat: c.latitude,
      lng: c.longitude,
      heading: Number.isFinite(c.heading) ? c.heading : null,
      speed: Number.isFinite(c.speed) ? c.speed : null,
      accuracy: Number.isFinite(c.accuracy) ? c.accuracy : null,
    };

    try{
      const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/update", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        credentials:"include",
        body: JSON.stringify(body),
      });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok===false) throw new Error(d.error || "Update failed");
      gpsState.textContent = "GPS: sending ✅";
      lastSend.textContent = "Last send: " + new Date().toLocaleString() + " • acc " + Math.round(Number(body.accuracy||0)) + "m";
      err.textContent = "";
    } catch(e){
      gpsState.textContent = "GPS: error";
      err.textContent = String(e.message || e);
    }
  }

  function startGps(){
    if(!navigator.geolocation) return toast("Geolocation not supported on this device");
    const k = runSel.value;
    if(!k) return toast("Select a runKey first");

    if (watchId) navigator.geolocation.clearWatch(watchId);
    watchId = navigator.geolocation.watchPosition(
      postFix,
      (e)=>{ gpsState.textContent = "GPS: error"; err.textContent = e.message || "GPS error"; },
      { enableHighAccuracy:true, maximumAge:1000, timeout:10000 }
    );
    toast("GPS broadcast started");
    gpsState.textContent = "GPS: starting…";
  }

  function stopGps(){
    if (watchId) navigator.geolocation.clearWatch(watchId);
    watchId = null;
    gpsState.textContent = "GPS: idle";
    toast("GPS broadcast stopped");
  }

  document.getElementById("enableBtn").addEventListener("click", enableTracking);
  document.getElementById("disableBtn").addEventListener("click", disableTracking);
  document.getElementById("startGps").addEventListener("click", startGps);
  document.getElementById("stopGps").addEventListener("click", stopGps);

  loadRuns().then(updateRunInfo).catch(e=>toast(String(e.message||e)));
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