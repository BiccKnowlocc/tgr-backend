// ======= MY NOTES =======
// 1) Space Points capacity system added to Order and Run schemas.
// 2) computeFeeBreakdown now dynamically accounts for ride-share fees.
// 3) Twilio SMS messages updated with professional/humorous copy for Shopping, Delivery, and Delivered.

// ======= server.js (FULL FILE) — TGR backend =======
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
const twilio = require("twilio");

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

const SESSION_COOKIE_SECURE =
  String(process.env.SESSION_COOKIE_SECURE || "").toLowerCase() === "true"
    ? true
    : process.env.NODE_ENV === "production";

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

// Twilio SMS Integration (optional)
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || "";

const twilioClient = (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) 
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) 
  : null;

// Square pay links (member portal quick buttons)
const SQUARE_PAY_GROCERIES_LINK =
  process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8";
const SQUARE_PAY_FEES_LINK =
  process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs";

// Membership purchase links
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

// Canada Post AddressComplete key
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
      secure: SESSION_COOKIE_SECURE,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

app.get("/favicon.ico", (_req, res) => res.status(204).end());

const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 },
});

// =========================
// PASSPORT
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
    rideLocal: 15,
    rideOwen: 50
  },
  groceryUnderMin: { threshold: 35, surcharge: 19 },
};

// Backend membership authority
const MEMBERSHIP_PLANS = {
  standard: {
    id: "standard",
    name: "Standard",
    monthlyPrice: 15,
    link: SQUARE_LINK_STANDARD,
    eligibility: "",
    perks: ["1 free add-on up to $10 OR $10 off zone fee monthly"],
  },
  route: {
    id: "route",
    name: "Route",
    monthlyPrice: 25,
    link: SQUARE_LINK_ROUTE,
    eligibility: "",
    perks: ["1 free add-on up to $10 OR $10 off zone fee monthly", "$5 off service fee on 1 order per run day"],
  },
  access: {
    id: "access",
    name: "Access",
    monthlyPrice: 12,
    link: SQUARE_LINK_ACCESS,
    eligibility: "Seniors 60+ or disabled / mobility-limited / low income",
    perks: ["1 free add-on up to $10 OR $10 off zone fee per run cycle", "$8 off service fee on 1 order per run day", "Free phone/text ordering"],
  },
  accesspro: {
    id: "accesspro",
    name: "Access Pro",
    monthlyPrice: 20,
    link: SQUARE_LINK_ACCESSPRO,
    eligibility: "Enhanced support tier",
    perks: ["$10 off service fee on 1 order per run day", "1 prescription pickup/delivery included monthly", "Document services included up to 10 pages/month in Tobermory area"],
  },
};

const MEMBERSHIP_ORDER = ["standard", "route", "access", "accesspro"];

function getPublicMembershipPlans() {
  return MEMBERSHIP_ORDER.map((id) => {
    const p = MEMBERSHIP_PLANS[id];
    return {
      id: p.id,
      name: p.name,
      monthlyPrice: p.monthlyPrice,
      priceLabel: `$${p.monthlyPrice} / month`,
      link: p.link,
      eligibility: p.eligibility,
      perks: p.perks,
    };
  });
}

function getEffectiveMemberTierForUser(user, requestedTier = "") {
  const activeTier =
    user &&
    user.membershipStatus === "active" &&
    user.membershipLevel &&
    user.membershipLevel !== "none"
      ? String(user.membershipLevel).trim().toLowerCase()
      : "";

  if (activeTier && MEMBERSHIP_PLANS[activeTier]) return activeTier;

  const reqTier = String(requestedTier || "").trim().toLowerCase();
  if (reqTier && MEMBERSHIP_PLANS[reqTier]) return reqTier;

  return "";
}

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
  if (!tier || !applyPerkYes) return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false };
  if (tier === "standard") return { serviceOff: 0, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };
  if (tier === "route") return { serviceOff: 5, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };
  if (tier === "access") return { serviceOff: 8, zoneOff: 10, freeAddonUpTo: 10, waitWaived: true };
  if (tier === "accesspro") return { serviceOff: 10, zoneOff: 0, freeAddonUpTo: 0, waitWaived: true };
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
    maxPoints: { type: Number, default: 10 }, // 10-point dynamic vehicle capacity
    minOrders: { type: Number, default: 6 },
    minFees: { type: Number, default: 0 },
    minLogic: { type: String, enum: ["OR", "AND"], default: "OR" },
    bookedOrdersCount: { type: Number, default: 0 },
    bookedPoints: { type: Number, default: 0 },
    bookedFeesTotal: { type: Number, default: 0 },
    lastRecalcAt: { type: Date },
  },
  { timestamps: true }
);

const AllowedStates = ["submitted", "confirmed", "shopping", "packed", "out_for_delivery", "delivered", "issue", "cancelled"];
const ACTIVE_STATES = new Set(["submitted", "confirmed", "shopping", "packed", "out_for_delivery"]);

const OrderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true, index: true },
    runKey: { type: String, required: true },
    runType: { type: String, enum: ["local", "owen"], required: true },
    spacePoints: { type: Number, default: 1 }, // Required cargo space points

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

    customer: {
      fullName: String,
      email: String,
      phone: String,
      altPhone: { type: String, default: "" },
      dob: { type: String, default: "" },
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

    addOns: {
      prescription: { requested: { type: Boolean, default: false }, pharmacyName: { type: String, default: "" }, notes: { type: String, default: "" } },
      liquor: { requested: { type: Boolean, default: false }, storeName: { type: String, default: "" }, notes: { type: String, default: "" }, idRequired: { type: Boolean, default: true } },
      printing: { requested: { type: Boolean, default: false }, pages: { type: Number, default: 0 }, notes: { type: String, default: "" } },
      fastFood: { requested: { type: Boolean, default: false }, restaurant: { type: String, default: "" }, orderDetails: { type: String, default: "" } },
      parcel: { requested: { type: Boolean, default: false }, carrier: { type: String, default: "" }, details: { type: String, default: "" } },
      bulky: { requested: { type: Boolean, default: false }, details: { type: String, default: "" } },
      ride: { requested: { type: Boolean, default: false }, pickupAddress: { type: String, default: "" }, preferredWindow: { type: String, default: "" }, notes: { type: String, default: "" } },
      generalNotes: { type: String, default: "" },
    },

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

    pricingSnapshot: { serviceFee: Number, zoneFee: Number, runFee: Number, addOnsFees: Number, surcharges: Number, discount: Number, totalFees: Number },

    payments: {
      fees: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null } },
      groceries: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null } },
    },

    status: { state: { type: String, enum: AllowedStates, default: "submitted" }, note: { type: String, default: "" }, updatedAt: { type: Date, default: Date.now }, updatedBy: { type: String, default: "system" } },
    statusHistory: { type: [{ state: { type: String, enum: AllowedStates }, note: String, at: Date, by: String }], default: [] },
    adminLog: { type: [{ at: Date, by: String, action: String, meta: Object }], default: [] },
  },
  { timestamps: true }
);

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

// Frequent Items Database
const CatalogueItemSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true, trim: true },
    category: { type: String, default: "General", trim: true },
    estimatedPrice: { type: Number, default: 0 },
    searchTokens: { type: [String], default: [] }
  },
  { timestamps: true }
);

CatalogueItemSchema.pre('save', function(next) {
  if (this.isModified('name') || this.isModified('category')) {
    const raw = `${this.name} ${this.category}`.toLowerCase().replace(/[^a-z0-9\s]/g, '');
    this.searchTokens = Array.from(new Set(raw.split(/\s+/).filter(t => t.length > 1)));
  }
  next();
});

const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const Tracking = mongoose.model("Tracking", TrackingSchema);
const CatalogueItem = mongoose.model("CatalogueItem", CatalogueItemSchema);

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

// Twilio SMS Helper
async function sendSms(toPhone, message) {
  console.log("\n====================================");
  console.log("TWILIO OUTBOUND SMS INITIATED");
  console.log("====================================");
  if (!twilioClient || !TWILIO_PHONE_NUMBER || !toPhone) {
    console.error("❌ SMS ABORTED: Missing credentials.");
    return;
  }
  try {
    let formattedPhone = String(toPhone).replace(/\D/g, "");
    if (formattedPhone.length === 10) formattedPhone = "+1" + formattedPhone;
    else if (formattedPhone.length === 11 && formattedPhone.startsWith("1")) formattedPhone = "+" + formattedPhone;
    
    await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: formattedPhone
    });
    console.log("✅ SMS SENT SUCCESSFULLY!");
  } catch (error) {
    console.error("❌ TWILIO ERROR:", String(error));
  }
}

function money(n) {
  const x = Number(n || 0);
  return x.toFixed(2);
}

function base64urlEncode(buf) { return Buffer.from(buf).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function base64urlDecodeToString(b64url) { const pad = b64url.length % 4 ? "=".repeat(4 - (b64url.length % 4)) : ""; const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/") + pad; return Buffer.from(b64, "base64").toString("utf8"); }
function signCancelToken(orderId, expMs) { const payload = `${orderId}.${String(expMs)}`; const sig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payload).digest(); return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`; }
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
    const a = Buffer.from(sigB64); const b = Buffer.from(expectedB64);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false };
    return { ok: true, expMs };
  } catch { return { ok: false }; }
}

function signTrackingToken(orderId, runKey, expMs) { const payload = `${orderId}.${runKey}.${String(expMs)}`; const sig = crypto.createHmac("sha256", TRACKING_TOKEN_SECRET).update(payload).digest(); return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`; }
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
    const a = Buffer.from(sigB64); const b = Buffer.from(expectedB64);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false };
    if (Date.now() > expMs) return { ok: false, error: "expired" };
    return { ok: true, orderId, runKey, expMs };
  } catch { return { ok: false }; }
}

async function nextOrderId(runType, runKey) {
  const type = String(runType || "").toLowerCase();
  const prefix = type === "owen" ? "OWEN" : "LOC";
  const datePart = String(runKey || "").slice(0, 10).replaceAll("-", "");
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
  } catch { return []; }
}

function computeFeeBreakdown(input) {
  const zone = String(input.zone || "");
  const runType = String(input.runType || "local");
  const extraStores = Array.isArray(input.extraStores) ? input.extraStores.map(String).map((s) => s.trim()).filter(Boolean) : safeJsonArray(input.extraStoresJson);
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
  
  // Apply ride-share fee based on run type
  if (String(input.addon_ride || "") === "yes") {
    addOnsFees += runType === "owen" ? PRICING.addOns.rideOwen : PRICING.addOns.rideLocal;
  }

  let surcharges = 0;
  if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) surcharges += PRICING.groceryUnderMin.surcharge;
  const serviceOff = Math.min(serviceFee, disc.serviceOff || 0);
  const optionA = Math.min(zoneFee, disc.zoneOff || 0);
  const optionB = Math.min(addOnsFees + runFee, disc.freeAddonUpTo || 0);
  const bestOr = Math.max(optionA, optionB);
  const discount = serviceOff + bestOr;
  const totalFees = Math.max(0, serviceFee + zoneFee + runFee + addOnsFees + surcharges - discount);
  return { totals: { serviceFee, zoneFee, runFee, addOnsFees, surcharges, discount, totalFees } };
}

// =========================
// RUN SCHEDULING
// =========================
function runKeyToDayjs(runKey) { try { const dateStr = String(runKey || "").slice(0, 10); const d = dayjs(dateStr).tz(TZ); return d.isValid() ? d : null; } catch { return null; } }
function nextDow(targetDow, from) { let d = dayjs(from).tz(TZ); const current = d.day(); let diff = (targetDow - current + 7) % 7; if (diff === 0) diff = 7; return d.add(diff, "day"); }
function computeTimesForDelivery(deliveryDayjs, type) {
  const delivery = dayjs(deliveryDayjs).tz(TZ);
  if (type === "local") {
    const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0);
    const opens = delivery.subtract(5, "day").hour(0).minute(0).second(0).millisecond(0);
    return { delivery, cutoff, opens };
  }
  const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0);
  const opens = delivery.subtract(6, "day").hour(0).minute(0).second(0).millisecond(0);
  return { delivery, cutoff, opens };
}
function runMinimumConfig(type) {
  if (type === "local") return { minOrders: 6, minFees: 200, minLogic: "OR", minimumText: "Minimum: 6 orders OR $200 booked fees" };
  return { minOrders: 6, minFees: 300, minLogic: "AND", minimumText: "Minimum: 6 orders AND $300 booked fees" };
}
function meetsMinimums(run) {
  if (run.minLogic === "AND") return run.bookedOrdersCount >= run.minOrders && run.bookedFeesTotal >= run.minFees;
  return run.bookedOrdersCount >= run.minOrders || run.bookedFeesTotal >= run.minFees;
}

async function getOrCreateNextRun(type) {
  const now = nowTz();
  let existing = await Run.findOne({ type, cutoffAt: { $gt: now.toDate() } }).sort({ opensAt: 1 }).lean();
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
  const created = await Run.create({ runKey, type, opensAt: opens.toDate(), cutoffAt: cutoff.toDate(), maxSlots: 12, maxPoints: 10, minOrders: cfg.minOrders, minFees: cfg.minFees, minLogic: cfg.minLogic });
  return created.toObject();
}

async function ensureUpcomingRuns() {
  const out = {};
  for (const type of ["local", "owen"]) {
    let run = await getOrCreateNextRun(type);
    const needsRecalc = !run.lastRecalcAt || dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(60, "second").toDate());
    if (needsRecalc) {
      const agg = await Order.aggregate([
        { $match: { runKey: run.runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } } }, 
        { $group: { _id: "$runKey", c: { $sum: 1 }, fees: { $sum: "$pricingSnapshot.totalFees" }, pts: { $sum: "$spacePoints" } } }
      ]);
      const c = agg?.[0]?.c || 0;
      const fees = agg?.[0]?.fees || 0;
      const pts = agg?.[0]?.pts || 0;
      await Run.updateOne({ runKey: run.runKey }, { $set: { bookedOrdersCount: c, bookedFeesTotal: fees, bookedPoints: pts, lastRecalcAt: new Date() } });
      run.bookedOrdersCount = c; run.bookedFeesTotal = fees; run.bookedPoints = pts; run.lastRecalcAt = new Date();
    }
    out[type] = run;
  }
  return out;
}

// =========================
// CATALOGUE API
// =========================
app.get("/api/public/catalogue/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().toLowerCase();
    if (!q || q.length < 2) return res.json({ ok: true, items: [] });
    
    const safeQ = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(safeQ, "i");
    
    const items = await CatalogueItem.find({
      $or: [{ name: re }, { category: re }]
    }).limit(15).lean();
    
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/admin/catalogue", requireLogin, requireAdmin, async (req, res) => {
  try {
    const items = await CatalogueItem.find().sort({ category: 1, name: 1 }).lean();
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/catalogue", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { name, category, estimatedPrice } = req.body;
    if (!name) return res.status(400).json({ ok: false, error: "Name is required" });
    
    const item = await CatalogueItem.findOneAndUpdate(
      { name: String(name).trim() },
      { 
        $set: { 
          category: String(category || "General").trim(), 
          estimatedPrice: Number(estimatedPrice || 0) 
        } 
      },
      { upsert: true, new: true }
    );
    res.json({ ok: true, item });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/catalogue/seed", requireLogin, requireAdmin, async (req, res) => {
  try {
    const defaults = [
      { name: "Milk (2%, 4L)", category: "Dairy", estimatedPrice: 6.49 },
      { name: "Milk (Skim, 2L)", category: "Dairy", estimatedPrice: 4.59 },
      { name: "Eggs (Large, 12)", category: "Dairy", estimatedPrice: 4.29 },
      { name: "Butter (Salted, 454g)", category: "Dairy", estimatedPrice: 6.99 },
      { name: "Cheddar Cheese (Block, 400g)", category: "Dairy", estimatedPrice: 7.99 },
      { name: "Yogurt (Vanilla, 650g tub)", category: "Dairy", estimatedPrice: 4.49 },
      { name: "Bread (White)", category: "Bakery", estimatedPrice: 3.49 },
      { name: "Bread (Whole Wheat)", category: "Bakery", estimatedPrice: 3.99 },
      { name: "Hot Dog Buns (12-pack)", category: "Bakery", estimatedPrice: 3.99 },
      { name: "Bananas (Bunch)", category: "Produce", estimatedPrice: 2.50 },
      { name: "Apples (Bag)", category: "Produce", estimatedPrice: 5.99 },
      { name: "Onions (Yellow, 3lb)", category: "Produce", estimatedPrice: 3.99 },
      { name: "Potatoes (Yellow, 10lb)", category: "Produce", estimatedPrice: 6.99 },
      { name: "Carrots (2lb bag)", category: "Produce", estimatedPrice: 2.99 },
      { name: "Romaine Lettuce (Head)", category: "Produce", estimatedPrice: 3.49 },
      { name: "Tomatoes (Vine, 4-pack)", category: "Produce", estimatedPrice: 4.99 },
      { name: "Oranges (Bag, 3lb)", category: "Produce", estimatedPrice: 6.99 },
      { name: "Ground Beef (Lean, 1lb)", category: "Meat", estimatedPrice: 7.99 },
      { name: "Chicken Breasts (Boneless, 3-pack)", category: "Meat", estimatedPrice: 12.99 },
      { name: "Bacon (500g)", category: "Meat", estimatedPrice: 7.49 },
      { name: "Hot Dogs (Wieners, 12-pack)", category: "Meat", estimatedPrice: 5.99 },
      { name: "Sliced Ham (Deli, 175g)", category: "Deli", estimatedPrice: 6.49 },
      { name: "Sliced Turkey (Deli, 175g)", category: "Deli", estimatedPrice: 6.99 },
      { name: "Cereal (Cheerios)", category: "Pantry", estimatedPrice: 5.49 },
      { name: "Peanut Butter (Smooth, 500g)", category: "Pantry", estimatedPrice: 6.49 },
      { name: "Pasta (Spaghetti, 500g)", category: "Pantry", estimatedPrice: 2.49 },
      { name: "Pasta Sauce (Tomato & Basil)", category: "Pantry", estimatedPrice: 3.49 },
      { name: "Coffee (Ground, 400g)", category: "Pantry", estimatedPrice: 8.99 },
      { name: "All-Purpose Flour (2.5kg)", category: "Pantry", estimatedPrice: 5.49 },
      { name: "White Sugar (2kg)", category: "Pantry", estimatedPrice: 3.99 },
      { name: "White Rice (Long Grain, 2kg)", category: "Pantry", estimatedPrice: 6.49 },
      { name: "Canned Soup (Chicken Noodle, 284ml)", category: "Pantry", estimatedPrice: 1.99 },
      { name: "Canned Soup (Tomato, 284ml)", category: "Pantry", estimatedPrice: 1.49 },
      { name: "Vegetable Oil (1L)", category: "Pantry", estimatedPrice: 5.99 },
      { name: "Olive Oil (1L)", category: "Pantry", estimatedPrice: 9.99 },
      { name: "Canned Baked Beans (398ml)", category: "Pantry", estimatedPrice: 1.99 },
      { name: "Canned Tuna (Flaked, 170g)", category: "Pantry", estimatedPrice: 2.29 },
      { name: "Tea Bags (Orange Pekoe, 72-pack)", category: "Pantry", estimatedPrice: 5.99 },
      { name: "Oatmeal (Instant, 10-pack)", category: "Pantry", estimatedPrice: 4.49 },
      { name: "Toilet Paper (12 Rolls)", category: "Household", estimatedPrice: 10.99 },
      { name: "Paper Towels (6 Rolls)", category: "Household", estimatedPrice: 8.99 },
      { name: "Dish Soap (800ml)", category: "Household", estimatedPrice: 3.99 },
      { name: "Laundry Detergent (Liquid, 1.36L)", category: "Household", estimatedPrice: 7.99 },
      { name: "Garbage Bags (Tall, 40-pack)", category: "Household", estimatedPrice: 8.99 },
      { name: "Meal Replacement Shakes (Vanilla, 6-pack)", category: "Pharmacy & Health", estimatedPrice: 14.99 },
      { name: "Meal Replacement Shakes (Chocolate, 6-pack)", category: "Pharmacy & Health", estimatedPrice: 14.99 },
      { name: "Acetaminophen / Pain Reliever (Reg. Strength, 100 tabs)", category: "Pharmacy & Health", estimatedPrice: 9.99 },
      { name: "Adult Incontinence Underwear (Large, Pack)", category: "Pharmacy & Health", estimatedPrice: 19.99 },
      { name: "Frozen Dinner (Meat & Potatoes)", category: "Frozen", estimatedPrice: 5.49 },
      { name: "Frozen Vegetables (Mixed, 750g)", category: "Frozen", estimatedPrice: 4.99 },
      { name: "Crackers (Saltines, Box)", category: "Snacks", estimatedPrice: 3.99 },
      { name: "Dog Food (Dry, 2kg bag)", category: "Pets", estimatedPrice: 11.99 },
      { name: "Cat Food (Canned, 156g)", category: "Pets", estimatedPrice: 1.29 },
      { name: "Cat Litter (Clumping, 7kg)", category: "Pets", estimatedPrice: 12.99 },
      { name: "Firewood (Bag)", category: "Outdoor", estimatedPrice: 10.00 },
      { name: "Insect Repellent (Aerosol)", category: "Outdoor", estimatedPrice: 8.99 },
      { name: "Marshmallows (Bag)", category: "Snacks", estimatedPrice: 3.49 }
    ];

    for (const item of defaults) {
      await CatalogueItem.findOneAndUpdate(
        { name: item.name },
        { $set: item },
        { upsert: true }
      );
    }
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.delete("/api/admin/catalogue/:id", requireLogin, requireAdmin, async (req, res) => {
  try {
    await CatalogueItem.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// TRACKING
// =========================
async function ensureTrackingDoc(runKey) {
  const t = await Tracking.findOneAndUpdate({ runKey }, { $setOnInsert: { runKey, enabled: false, startedAt: null, stoppedAt: null, updatedBy: "system" } }, { upsert: true, new: true }).lean();
  return t;
}

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
    if (!ACTIVE_STATES.has(state)) return res.status(403).json({ ok: false, error: "Tracking is only available for active orders." });
    const t = await ensureTrackingDoc(runKey);
    if (!t.enabled) return res.json({ ok: true, enabled: false, hasFix: false });
    if (!t.lastAt || typeof t.lastLat !== "number" || typeof t.lastLng !== "number") return res.json({ ok: true, enabled: true, hasFix: false });
    res.json({ ok: true, enabled: true, hasFix: true, last: { lat: t.lastLat, lng: t.lastLng, heading: t.lastHeading, speed: t.lastSpeed, accuracy: t.lastAccuracy, at: t.lastAt } });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// AddressComplete proxy
// =========================
function proxyRemote(url, res, contentType) {
  res.setHeader("Cache-Control", "no-store, max-age=0"); res.setHeader("Content-Type", contentType);
  https.get(url, (r) => {
    if (r.statusCode && r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) return proxyRemote(r.headers.location, res, contentType);
    if (r.statusCode !== 200) {
      res.statusCode = 502; let body = ""; r.on("data", (c) => (body += c.toString("utf8"))); r.on("end", () => { res.end(`Upstream error (${r.statusCode}): ${body.slice(0, 400)}`); });
      return;
    }
    r.pipe(res);
  }).on("error", (e) => { res.statusCode = 502; res.end("Proxy error: " + String(e)); });
}

app.get("/vendor/addresscomplete.css", (_req, res) => { proxyRemote(`https://ws1.postescanada-canadapost.ca/css/addresscomplete-2.30.min.css?key=${encodeURIComponent(CANADAPOST_KEY)}`, res, "text/css; charset=utf-8"); });
app.get("/vendor/addresscomplete.js", (_req, res) => { proxyRemote(`https://ws1.postescanada-canadapost.ca/js/addresscomplete-2.30.min.js?key=${encodeURIComponent(CANADAPOST_KEY)}`, res, "application/javascript; charset=utf-8"); });
app.get("/api/public/addresscomplete", (_req, res) => { res.json({ ok: true, css: `https://api.tobermorygroceryrun.ca/vendor/addresscomplete.css`, js: `https://api.tobermorygroceryrun.ca/vendor/addresscomplete.js` }); });

// =========================
// PUBLIC CONFIG
// =========================
app.get("/api/public/config", (_req, res) => { res.json({ ok: true, mapboxPublicToken: MAPBOX_PUBLIC_TOKEN || "", canadaPostKey: CANADAPOST_KEY || "", squareMembershipLinks: { standard: SQUARE_LINK_STANDARD, route: SQUARE_LINK_ROUTE, access: SQUARE_LINK_ACCESS, accesspro: SQUARE_LINK_ACCESSPRO } }); });
app.get("/api/public/memberships", (_req, res) => { res.json({ ok: true, plans: getPublicMembershipPlans() }); });

// =========================
// AUTH ROUTES
// =========================
app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) return res.status(500).send("Google auth is not configured on this server.");
  const rt = String(req.query.returnTo || "").trim();
  const state = rt === "popup" ? "popup" : "home";
  return passport.authenticate("google", { scope: ["profile", "email"], state })(req, res, next);
});

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: PUBLIC_SITE_URL + "/?login=failed" }), async (req, res) => {
  const state = String(req.query.state || "");
  if (state === "popup") return res.send("<script>window.close();</script>");
  try {
    const u = await User.findById(req.user._id).lean();
    if (!isProfileComplete(u?.profile || {})) return res.redirect(PUBLIC_SITE_URL + "/?tab=account&onboarding=1");
  } catch {}
  res.redirect(PUBLIC_SITE_URL + "/");
});
app.get("/logout", (req, res) => { const returnTo = String(req.query.returnTo || (PUBLIC_SITE_URL + "/")).trim(); req.session.destroy(() => res.redirect(returnTo)); });

// =========================
// API: ME + PROFILE
// =========================
app.get("/api/me", (req, res) => { const u = req.user; const activeTier = getEffectiveMemberTierForUser(u); res.json({ ok: true, loggedIn: !!u, email: u?.email || null, name: u?.name || "", photo: u?.photo || "", membershipLevel: u?.membershipLevel || "none", membershipStatus: u?.membershipStatus || "inactive", effectiveMembershipTier: activeTier || "", renewalDate: u?.renewalDate || null, profileComplete: isProfileComplete(u?.profile || {}), isAdmin: !!u?.email && isAdminEmail(u.email) }); });
app.get("/api/profile", requireLogin, async (req, res) => { const u = await User.findById(req.user._id).lean(); res.json({ ok: true, profile: u?.profile || {}, profileComplete: isProfileComplete(u?.profile || {}), email: u?.email || "", name: u?.name || "", photo: u?.photo || "" }); });
app.post("/api/profile", requireLogin, async (req, res) => {
  try {
    const b = req.body || {};
    const u = await User.findById(req.user._id);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });
    const addresses = Array.isArray(b.addresses) ? b.addresses : [];
    const newProfile = {
      version: 1, fullName: String(b.fullName || "").trim(), preferredName: String(b.preferredName || "").trim(), phone: String(b.phone || "").trim(), altPhone: String(b.altPhone || "").trim(), contactPref: String(b.contactPref || "").trim(), contactAuth: yn(b.contactAuth),
      subsDefault: String(b.subsDefault || "").trim(), dropoffDefault: String(b.dropoffDefault || "").trim(),
      customerType: String(b.customerType || "").trim(), accessibility: String(b.accessibility || "").trim(), dietary: String(b.dietary || "").trim(), notes: String(b.notes || "").trim(),
      addresses: addresses.map((a) => ({ id: String(a.id || "").trim() || String(Math.random()).slice(2), label: String(a.label || "").trim(), town: String(a.town || "").trim(), zone: String(a.zone || "").trim(), streetAddress: String(a.streetAddress || "").trim(), unit: String(a.unit || "").trim(), postalCode: String(a.postalCode || "").trim(), instructions: String(a.instructions || "").trim(), gateCode: String(a.gateCode || "").trim() })),
      defaultId: String(b.defaultId || "").trim(), consentTerms: yn(b.consentTerms), consentPrivacy: yn(b.consentPrivacy), consentMarketing: yn(b.consentMarketing),
    };
    if (!newProfile.defaultId && newProfile.addresses.length) newProfile.defaultId = newProfile.addresses[0].id;
    newProfile.complete = isProfileComplete(newProfile); newProfile.completedAt = newProfile.complete ? new Date().toISOString() : null;
    u.profile = newProfile; u.markModified("profile"); await u.save();
    res.json({ ok: true, profileComplete: newProfile.complete === true, profile: newProfile });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// RUNS + ESTIMATOR
// =========================
app.get("/api/runs/active", async (_req, res) => {
  try {
    const runs = await ensureUpcomingRuns();
    const now = nowTz(); const out = {};
    for (const type of ["local", "owen"]) {
      const run = runs[type]; const opensAt = dayjs(run.opensAt).tz(TZ); const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
      const windowOpen = now.isAfter(opensAt) && now.isBefore(cutoffAt); const slotsRemaining = Math.max(0, (run.maxSlots || 12) - (run.bookedOrdersCount || 0));
      const minCfg = runMinimumConfig(type);
      out[type] = { runKey: run.runKey, type: run.type, maxSlots: run.maxSlots || 12, bookedOrdersCount: run.bookedOrdersCount || 0, bookedFeesTotal: run.bookedFeesTotal || 0, slotsRemaining, isOpen: windowOpen && slotsRemaining > 0, opensAtLocal: fmtLocal(run.opensAt), cutoffAtLocal: fmtLocal(run.cutoffAt), meetsMinimums: meetsMinimums(run), minimumText: minCfg.minimumText, cutoffAtISO: run.cutoffAt, opensAtISO: run.opensAt };
    }
    res.json({ ok: true, runs: out });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/estimator", (req, res) => {
  try {
    const effectiveMemberTier = getEffectiveMemberTierForUser(req.user, req.body?.memberTier || "");
    const breakdown = computeFeeBreakdown({ ...(req.body || {}), memberTier: effectiveMemberTier, applyPerk: "yes" });
    res.json({ ok: true, effectiveMemberTier, breakdown });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// ORDERS
// =========================
function pickDefaultAddress(profile) { const p = profile || {}; const arr = Array.isArray(p.addresses) ? p.addresses : []; if (!arr.length) return null; const defId = String(p.defaultId || "").trim(); const found = defId ? arr.find((a) => String(a.id) === defId) : null; return found || arr[0] || null; }

app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};
    const user = await User.findById(req.user._id).lean();
    const profile = user?.profile || {};

    if (!yn(b.consent_terms) || !yn(b.consent_accuracy) || !yn(b.consent_dropoff)) return res.status(400).json({ ok: false, error: "All required consents must be accepted." });

    const dob = String(b.dob || "").trim(); const altPhone = String(b.altPhone || "").trim();
    const addPrescription = yn(b.addon_prescription); const addLiquor = yn(b.addon_liquor); const addPrinting = yn(b.addon_printing); const addFastFood = yn(b.addon_fastfood); const addParcel = yn(b.addon_parcel); const addBulky = yn(b.addon_bulky); const addRide = yn(b.addon_ride);
    const prescriptionPharmacy = String(b.prescriptionPharmacy || "").trim(); const prescriptionNotes = String(b.prescriptionNotes || "").trim();
    const liquorStore = String(b.liquorStore || "").trim(); const liquorNotes = String(b.liquorNotes || "").trim();
    const printingNotes = String(b.printingNotes || "").trim();
    const fastFoodRestaurant = String(b.fastFoodRestaurant || "").trim(); const fastFoodOrder = String(b.fastFoodOrder || "").trim();
    const parcelCarrier = String(b.parcelCarrier || "").trim(); const parcelDetails = String(b.parcelDetails || "").trim();
    const bulkyDetails = String(b.bulkyDetails || "").trim();
    const ridePickup = String(b.ridePickup || "").trim(); const rideWindow = String(b.rideWindow || "").trim(); const rideNotes = String(b.rideNotes || "").trim();
    const generalNotes = String(b.optionalNotes || "").trim();
    const gateCode = String(b.gateCode || "").trim(); const buildingAccessNotes = String(b.buildingAccessNotes || "").trim(); const parkingNotes = String(b.parkingNotes || "").trim(); const budgetCap = Math.max(0, Number(b.budgetCap || 0)); const receiptPreference = String(b.receiptPreference || "").trim(); const photoProofOk = yn(b.photoProofOk);

    const runs = await ensureUpcomingRuns();
    const runType = String(b.runType || ""); const run = runs[runType];
    if (!run) return res.status(400).json({ ok: false, error: "Invalid runType." });

    const now = nowTz(); const opensAt = dayjs(run.opensAt).tz(TZ); const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    if (!(now.isAfter(opensAt) && now.isBefore(cutoffAt))) return res.status(403).json({ ok: false, error: "Ordering is closed for this run." });

    const defAddr = pickDefaultAddress(profile);
    const fullName = String(b.fullName || profile.fullName || user.name || "").trim(); const phone = String(b.phone || profile.phone || "").trim();
    const town = String(b.town || defAddr?.town || "").trim(); const streetAddress = String(b.streetAddress || defAddr?.streetAddress || "").trim(); const unit = String(b.unit || defAddr?.unit || "").trim(); const postalCode = String(b.postalCode || defAddr?.postalCode || "").trim(); const zone = String(b.zone || defAddr?.zone || "").trim();
    const primaryStore = String(b.primaryStore || "").trim(); const groceryList = String(b.groceryList || "").trim();
    const dropoffPref = String(b.dropoffPref || profile.dropoffDefault || "").trim(); const subsPref = String(b.subsPref || profile.subsDefault || "").trim(); const contactPref = String(b.contactPref || profile.contactPref || "").trim();

    const required = [["fullName", fullName], ["phone", phone], ["town", town], ["streetAddress", streetAddress], ["postalCode", postalCode], ["zone", zone], ["runType", runType], ["primaryStore", primaryStore], ["groceryList", groceryList], ["dropoffPref", dropoffPref], ["subsPref", subsPref], ["contactPref", contactPref]];
    for (const [k, v] of required) { if (!String(v || "").trim()) return res.status(400).json({ ok: false, error: "Missing required field: " + k }); }

    const orderId = await nextOrderId(runType, run.runKey);
    const extraStores = safeJsonArray(b.extraStores);
    let attachment = null;
    if (req.file) attachment = { originalName: req.file.originalname, mimeType: req.file.mimetype, size: req.file.size, path: req.file.path };

    const effectiveMemberTier = getEffectiveMemberTierForUser(user, "");
    
    // Space Point Calculation
    let spacePoints = 1;
    if (addBulky) spacePoints += 1;
    if (addRide) spacePoints += 2;

    const pricingSnapshot = computeFeeBreakdown({ zone, runType, extraStores, grocerySubtotal: Number(b.grocerySubtotal || 0), addon_printing: b.addon_printing || "no", addon_ride: b.addon_ride || "no", printPages: Number(b.printPages || 0), memberTier: effectiveMemberTier, applyPerk: "yes" }).totals;

    // Check Capacity
    const maxPoints = run.maxPoints || 10;
    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedPoints: { $lte: maxPoints - spacePoints } }, 
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees, bookedPoints: spacePoints }, $set: { lastRecalcAt: new Date() } }, 
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: `Vehicle capacity reached! This order requires ${spacePoints} space points, but the Jeep is too full.` });

    const created = await Order.create({
      orderId, runKey: run.runKey, runType, spacePoints, hold: false,
      flags: { prescription: addPrescription, alcohol: addLiquor, bulky: addBulky, idRequired: addLiquor },
      customer: { fullName, email: String(user.email || "").trim().toLowerCase(), phone, altPhone, dob },
      address: { town, streetAddress, unit, postalCode, zone }, stores: { primary: primaryStore, extra: extraStores }, preferences: { dropoffPref, subsPref, contactPref, contactAuth: true },
      addOns: { prescription: { requested: addPrescription, pharmacyName: prescriptionPharmacy, notes: prescriptionNotes }, liquor: { requested: addLiquor, storeName: liquorStore, notes: liquorNotes, idRequired: true }, printing: { requested: addPrinting, pages: Math.max(0, Number(b.printPages || 0)), notes: printingNotes }, fastFood: { requested: addFastFood, restaurant: fastFoodRestaurant, orderDetails: fastFoodOrder }, parcel: { requested: addParcel, carrier: parcelCarrier, details: parcelDetails }, bulky: { requested: addBulky, details: bulkyDetails }, ride: { requested: addRide, pickupAddress: ridePickup, preferredWindow: rideWindow, notes: rideNotes }, generalNotes },
      deliveryMeta: { gateCode, buildingAccessNotes, parkingNotes, budgetCap, receiptPreference, photoProofOk },
      list: { groceryListText: groceryList, attachment }, consents: { terms: true, accuracy: true, dropoff: true }, pricingSnapshot,
      payments: { fees: { status: "unpaid" }, groceries: { status: "unpaid" } }, status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" }, statusHistory: [{ state: "submitted", note: "", at: new Date(), by: "customer" }],
      adminLog: [{ at: new Date(), by: "system", action: "order_created", meta: { runKey: run.runKey, effectiveMemberTier } }],
    });

    const cancelUntilMs = cutoffAt.toDate().getTime();
    const cancelToken = signCancelToken(orderId, cancelUntilMs);
    const cancelUntilLocal = fmtLocal(cutoffAt.toDate());

    pmSend(created.customer?.email, `TGR Order Received: ${created.orderId}`, `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;"><h2 style="margin:0 0 10px;">Order received ✅</h2><p style="margin:0 0 10px;"><strong>Order ID:</strong> ${escapeHtml(created.orderId)}</p><p style="margin:0 0 10px;"><strong>Run:</strong> ${escapeHtml(created.runKey)} (${escapeHtml(created.runType)})</p><p style="margin:0 0 10px;"><strong>Fees estimate:</strong> $${escapeHtml(money(created.pricingSnapshot?.totalFees || 0))}</p>${effectiveMemberTier ? `<p style="margin:0 0 10px;"><strong>Membership applied:</strong> ${escapeHtml(effectiveMemberTier)}</p>` : ""}<p style="margin:0;">Member Portal: <a href="${escapeHtml("https://api.tobermorygroceryrun.ca/member")}">${escapeHtml("https://api.tobermorygroceryrun.ca/member")}</a></p></div>`, `Order received\nOrder ID: ${created.orderId}\nRun: ${created.runKey} (${created.runType})\nFees estimate: $${money(created.pricingSnapshot?.totalFees || 0)}\n${effectiveMemberTier ? `Membership applied: ${effectiveMemberTier}\n` : ""}`);
    res.json({ ok: true, orderId, runKey: run.runKey, cancelToken, cancelUntilLocal, effectiveMemberTier });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// STATUS UPDATE ENDPOINT (WITH TWILIO SMS INTEGRATION)
app.post("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); 
    const state = String(req.body?.state || "").trim(); 
    const note = String(req.body?.note || "").trim(); 
    const by = adminBy(req);

    if (!AllowedStates.includes(state)) return res.status(400).json({ ok: false, error: "Invalid state" });
    
    const order = await Order.findOne({ orderId }); 
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    
    const oldState = order.status.state;

    order.status.state = state; 
    order.status.note = note; 
    order.status.updatedAt = new Date(); 
    order.status.updatedBy = by; 
    order.statusHistory.push({ state, note, at: new Date(), by });
    
    await order.save(); 

    // Trigger SMS if state changed to a key customer milestone
    if (oldState !== state) {
      const phone = order.customer?.phone;
      const firstName = order.customer?.fullName?.split(' ')[0] || 'there';

      if (phone) {
        let smsMessage = "";
        
        if (state === "shopping") {
          smsMessage = `Hi ${firstName}! I've grabbed a cart and I'm officially picking your groceries. Let's hope the avocados are cooperating today. 🥑 - Tobermory Grocery Run`;
        } 
        else if (state === "out_for_delivery") {
          // Generate tracking link
          const run = await Run.findOne({ runKey: order.runKey }).lean();
          let trackingLink = "";
          if (run) {
            const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf();
            const token = signTrackingToken(order.orderId, run.runKey, expMs);
            trackingLink = `${PUBLIC_SITE_URL}/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(token)}&orderId=${encodeURIComponent(order.orderId)}`;
          }
          smsMessage = `Hi ${firstName}, the Jeep is loaded and I'm on the road! Track your delivery live right here: ${trackingLink} 🚙💨 - TGR`;
        } 
        else if (state === "delivered") {
          smsMessage = `Mission accomplished! Your order has been dropped off. Enjoy the goodies, and thanks for trusting Tobermory Grocery Run! 🛒✨`;
        }

        if (smsMessage) {
          await sendSms(phone, smsMessage);
        }
      }
    }

    res.json({ ok: true });
  } catch (e) { 
    res.status(500).json({ ok: false, error: String(e) }); 
  }
});

app.post("/api/admin/orders/:orderId/payments", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const feesStatus = String(req.body?.feesStatus || "").trim(); const groceriesStatus = String(req.body?.groceriesStatus || "").trim(); const note = String(req.body?.note || "").trim();
    const order = await Order.findOne({ orderId }); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    if (feesStatus) { order.payments.fees.status = feesStatus; order.payments.fees.paidAt = feesStatus === "paid" ? new Date() : null; }
    if (groceriesStatus) { order.payments.groceries.status = groceriesStatus; order.payments.groceries.paidAt = (groceriesStatus === "paid" || groceriesStatus === "deposit_paid") ? new Date() : null; }
    if (note) { order.payments.fees.note = note; order.payments.groceries.note = note; }
    await order.save(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});
app.post("/api/admin/orders/:orderId/cancel", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const reason = String(req.body?.reason || "").trim() || "Cancelled by admin"; const by = adminBy(req);
    const order = await Order.findOne({ orderId }); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    if (wasActive) { const fees = Number(order.pricingSnapshot?.totalFees || 0); await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }); }
    order.status.state = "cancelled"; order.status.note = reason; order.status.updatedAt = new Date(); order.status.updatedBy = by; order.statusHistory.push({ state: "cancelled", note: reason, at: new Date(), by });
    await order.save(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});
app.delete("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean(); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    if (wasActive) { const fees = Number(order.pricingSnapshot?.totalFees || 0); await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } }); }
    await Order.deleteOne({ orderId }); res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/admin/tracking/:runKey/start", requireLogin, requireAdmin, async (req, res) => { try { const runKey = String(req.params.runKey || "").trim(); const by = adminBy(req); await ensureTrackingDoc(runKey); await Tracking.updateOne({ runKey }, { $set: { enabled: true, startedAt: new Date(), stoppedAt: null, updatedBy: by } }); res.json({ ok: true, runKey }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.post("/api/admin/tracking/:runKey/stop", requireLogin, requireAdmin, async (req, res) => { try { const runKey = String(req.params.runKey || "").trim(); const by = adminBy(req); await ensureTrackingDoc(runKey); await Tracking.updateOne({ runKey }, { $set: { enabled: false, stoppedAt: new Date(), updatedBy: by } }); res.json({ ok: true, runKey }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.post("/api/admin/tracking/:runKey/update", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim(); const by = adminBy(req); const lat = Number(req.body?.lat); const lng = Number(req.body?.lng); const heading = Number(req.body?.heading); const speed = Number(req.body?.speed); const accuracy = Number(req.body?.accuracy);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return res.status(400).json({ ok: false, error: "lat/lng required" });
    await ensureTrackingDoc(runKey);
    await Tracking.updateOne({ runKey }, { $set: { lastLat: lat, lastLng: lng, lastHeading: Number.isFinite(heading) ? heading : null, lastSpeed: Number.isFinite(speed) ? speed : null, lastAccuracy: Number.isFinite(accuracy) ? accuracy : null, lastAt: new Date(), updatedBy: by } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});
app.get("/api/admin/orders/:orderId/tracking-link", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const o = await Order.findOne({ orderId }).lean(); if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
    const run = await Run.findOne({ runKey: o.runKey }).lean(); if (!run) return res.status(404).json({ ok: false, error: "Run not found" });
    const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf(); const token = signTrackingToken(o.orderId, run.runKey, expMs);
    const url = `https://api.tobermorygroceryrun.ca/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(token)}&orderId=${encodeURIComponent(o.orderId)}`;
    res.json({ ok: true, url });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// ADMIN MASTER LIST GENERATOR
// =========================
app.get("/api/admin/runs/:runKey/master-list", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    if (!runKey) return res.status(400).json({ok: false, error: "Run key required"});

    const orders = await Order.find({
      runKey,
      "status.state": { $in: ["submitted", "confirmed", "shopping", "packed"] }
    }).lean();

    const tally = {};
    const extraStops = [];

    for (const o of orders) {
      if (o.list && o.list.groceryListText) {
        const lines = o.list.groceryListText.split(/\r?\n/);
        for (const line of lines) {
          let text = line.replace(/^•\s*/, '').trim();
          if (!text) continue;
          
          const key = text.toLowerCase();
          if (!tally[key]) tally[key] = { name: text, count: 0 };
          tally[key].count += 1;
        }
      }
      
      if (o.stores && Array.isArray(o.stores.extra)) {
        for (const stop of o.stores.extra) {
          if (stop.trim()) extraStops.push(`${stop.trim()} (Order: ${o.orderId})`);
        }
      }
    }

    const sortedItems = Object.values(tally).sort((a, b) => a.name.localeCompare(b.name));
    res.json({ ok: true, runKey, items: sortedItems, extraStops });
  } catch(e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});


// =========================
// ADMIN PAGE (Includes Master List UI)
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
  :root{ --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14); --text:#fff; --muted:rgba(255,255,255,.75); --red:#e3342f; --red2:#ff4a44; --radius:14px; }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1400px;margin:0 auto;padding:16px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .btn{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-weight:900;border-radius:999px;padding:10px 14px;cursor:pointer;text-decoration:none;white-space:nowrap;}
  .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);}
  .btn.ghost{background:transparent;}
  .muted{color:var(--muted);}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
  input,select,textarea{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.22);color:#fff;font-size:15px;outline:none;}
  textarea{min-height:90px;resize:vertical;}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;}
  th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;}
  .grid{display:grid;grid-template-columns: 1.1fr .9fr; gap:12px;}
  @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} }
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
  .toast.show{display:block;}
  .modalBack{position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; align-items:center; justify-content:center; padding:16px; z-index:100;}
  .modal{width:min(980px, 100%); max-height:92vh; overflow:auto; border:1px solid rgba(255,255,255,.16); background:#0b0b0b; border-radius:16px; padding:14px;}
  .k{font-size:12px;color:rgba(255,255,255,.7);text-transform:uppercase;letter-spacing:.08em;}
  .v{font-weight:900;}
  .two{display:grid;grid-template-columns:1fr 1fr; gap:10px;}
  @media(max-width:800px){.two{grid-template-columns:1fr;}}
  pre{white-space:pre-wrap; word-break:break-word;}
  
  /* Print styling specifically for the Master List Modal */
  @media print {
    body * { visibility: hidden; }
    #masterListModalBack, #masterListModalBack * { visibility: visible; }
    #masterListModalBack { position: absolute; left: 0; top: 0; background: white; color: black; align-items: flex-start; }
    .modal { border: none; background: white; box-shadow: none; overflow: visible; max-height: none; }
    .btn, .toast { display: none !important; }
    .card { background: white !important; border: none !important; color: black !important; }
    pre { color: black !important; font-family: monospace; font-size: 14pt; }
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div>
        <div style="font-weight:1000;font-size:22px;">Admin Command Center</div>
        <div class="muted">Manage orders, tracking, and grocery catalogue.</div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn" href="/admin/tracking-control">Tracking Control</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>
    <div class="toast" id="toast"></div>

    <div class="hr" style="margin-top:16px; margin-bottom:16px;"></div>

    <div class="row" style="margin-bottom:14px;">
      <button class="btn primary" id="tabBtnOrders" onclick="switchTab('orders')">Orders Management</button>
      <button class="btn" id="tabBtnCatalogue" onclick="switchTab('catalogue')">Catalogue / Inventory</button>
    </div>

    <div id="tabContentOrders">
      <div class="grid">
        <div class="card" style="box-shadow:none;">
          <div style="font-weight:1000;">Search / Filters</div>
          <div class="hr"></div>
          <div class="row">
            <div style="flex: 2 1 320px;"><label class="muted" style="font-weight:900;">Search</label><input id="q" placeholder="orderId, name, email, phone, address" /></div>
            <div style="flex: 1 1 180px;"><label class="muted" style="font-weight:900;">State</label><select id="state"><option value="">Any</option><option>submitted</option><option>confirmed</option><option>shopping</option><option>packed</option><option>out_for_delivery</option><option>delivered</option><option>issue</option><option>cancelled</option></select></div>
            <div style="flex: 1 1 180px;"><label class="muted" style="font-weight:900;">Run Key</label><input id="runKey" placeholder="YYYY-MM-DD-local" /></div>
          </div>
          <div class="row">
            <div style="flex: 1 1 160px;"><label class="muted" style="font-weight:900;">Zone</label><select id="zone"><option value="">Any</option><option>A</option><option>B</option><option>C</option><option>D</option></select></div>
            <div style="flex: 1 1 220px;"><label class="muted" style="font-weight:900;">Town</label><input id="town" placeholder="e.g., Tobermory" /></div>
            <div style="flex: 1 1 220px;"><label class="muted" style="font-weight:900;">Flag</label><select id="flag"><option value="">Any</option><option value="idRequired">idRequired</option><option value="prescription">prescription</option><option value="alcohol">alcohol</option><option value="bulky">bulky</option><option value="needsContact">needsContact</option><option value="newCustomerDepositRequired">newCustomerDepositRequired</option></select></div>
          </div>
          <div class="row">
            <label class="row" style="gap:8px;"><input id="unpaidFees" type="checkbox" style="width:18px;height:18px;"><span class="muted" style="font-weight:900;">Unpaid fees only</span></label>
            <label class="row" style="gap:8px;"><input id="hold" type="checkbox" style="width:18px;height:18px;"><span class="muted" style="font-weight:900;">Hold only</span></label>
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
          <div class="muted">Enter a runKey to export Routific CSV or generate a Master Shopping List:</div>
          <div class="row" style="margin-top:10px;">
            <div style="flex:1 1 200px;"><input id="toolRunKey" placeholder="YYYY-MM-DD-local" /></div>
            <button class="btn" id="exportBtn">Download CSV</button>
            <button class="btn primary" id="masterListBtn">Master Shopping List</button>
          </div>
          <div class="hr"></div>
          <div class="muted">Tip: click Open on any row to view full order details and controls.</div>
        </div>
      </div>
      <div class="hr"></div>
      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Order</th><th>Customer</th><th>Address</th><th>Run</th><th>Status</th><th>Fees</th><th>Flags</th><th>Actions</th></tr></thead>
          <tbody id="rows"><tr><td colspan="8" class="muted">Loading…</td></tr></tbody>
        </table>
      </div>
    </div>

    <div id="tabContentCatalogue" style="display:none;">
      <div class="grid">
        <div class="card" style="box-shadow:none;">
          <div style="font-weight:1000;">Add New Item</div>
          <div class="hr"></div>
          <div class="row">
             <div style="flex: 2 1 200px;"><label class="muted" style="font-weight:900;">Item Name (e.g. Milk 2% 4L)</label><input id="catName" placeholder="Item Name" /></div>
          </div>
          <div class="row">
             <div style="flex: 1 1 150px;"><label class="muted" style="font-weight:900;">Category</label><input id="catCategory" placeholder="Dairy, Produce, etc." /></div>
             <div style="flex: 1 1 100px;"><label class="muted" style="font-weight:900;">Est Price ($)</label><input id="catPrice" type="number" step="0.01" placeholder="5.99" /></div>
          </div>
          <div class="row" style="margin-top:12px;">
             <button class="btn primary" id="addCatBtn">Add Item</button>
             <button class="btn ghost" id="seedCatBtn">Seed Defaults</button>
          </div>
        </div>
        <div class="card" style="box-shadow:none;">
          <div style="font-weight:1000;">Catalogue Stats</div>
          <div class="hr"></div>
          <div class="muted">These items will auto-complete for customers in the order form.</div>
          <div class="row" style="margin-top:12px;">
             <span class="pill" id="catCountPill">Items: 0</span>
          </div>
        </div>
      </div>
      <div class="hr"></div>
      <div style="overflow:auto;">
        <table>
          <thead><tr><th>Item Name</th><th>Category</th><th>Est Price</th><th>Actions</th></tr></thead>
          <tbody id="catRows"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<div class="modalBack" id="modalBack">
  <div class="modal">
    <div class="row" style="justify-content:space-between;"><div style="font-weight:1000;font-size:20px;">Order Details</div><button class="btn ghost" id="closeModal">Close</button></div>
    <div class="hr"></div>
    <div class="two">
      <div class="card" style="box-shadow:none;">
        <div class="k">Order ID</div><div class="v" id="m_orderId">—</div><div class="hr"></div>
        <div class="k">Customer</div><div class="v" id="m_customer">—</div>
        <div class="k">Phone</div><div class="v" id="m_phone">—</div>
        <div class="k">Alt Phone</div><div class="v" id="m_altPhone">—</div>
        <div class="k">Email</div><div class="v" id="m_email">—</div>
        <div class="k">DOB</div><div class="v" id="m_dob">—</div><div class="hr"></div>
        <div class="k">Address</div><div class="v" id="m_addr">—</div>
        <div class="k">Zone</div><div class="v" id="m_zone">—</div>
        <div class="k">Run</div><div class="v" id="m_run">—</div>
      </div>
      <div class="card" style="box-shadow:none;">
        <div class="k">Fees total</div><div class="v" id="m_fees">—</div>
        <div class="k">Fees payment</div><div class="v" id="m_feesCurrent">—</div>
        <div class="k">Groceries payment</div><div class="v" id="m_groceriesCurrent">—</div><div class="hr"></div>
        <label class="muted" style="font-weight:900;">Status state</label>
        <select id="m_state"><option>submitted</option><option>confirmed</option><option>shopping</option><option>packed</option><option>out_for_delivery</option><option>delivered</option><option>issue</option><option>cancelled</option></select>
        <label class="muted" style="font-weight:900;">Status note (optional)</label><input id="m_stateNote" placeholder="Short note" />
        <div class="row" style="margin-top:10px;"><button class="btn primary" id="m_saveState">Save status</button><button class="btn" id="m_trackingLink">Copy tracking link</button></div><div class="hr"></div>
        <div class="row">
          <div style="flex:1 1 200px;"><label class="muted" style="font-weight:900;">Fees status</label><select id="m_feesStatus"><option value="">(no change)</option><option value="unpaid">unpaid</option><option value="paid">paid</option></select></div>
          <div style="flex:1 1 200px;"><label class="muted" style="font-weight:900;">Groceries status</label><select id="m_groceriesStatus"><option value="">(no change)</option><option value="unpaid">unpaid</option><option value="deposit_paid">deposit_paid</option><option value="paid">paid</option></select></div>
        </div>
        <label class="muted" style="font-weight:900;">Payment note (optional)</label><input id="m_payNote" placeholder="e.g., paid cash, e-transfer, Square receipt #" />
        <div class="row" style="margin-top:10px;"><button class="btn" id="m_savePay">Save payments</button><button class="btn" id="m_cancelAdmin">Cancel order</button><button class="btn ghost" id="m_deleteOrder">Delete order</button></div>
      </div>
    </div>
    <div class="hr"></div>
    <div class="two">
      <div class="card" style="box-shadow:none;"><div style="font-weight:1000;">Grocery list</div><div class="hr"></div><pre id="m_list"></pre></div>
      <div class="card" style="box-shadow:none;"><div style="font-weight:1000;">Add-ons / notes</div><div class="hr"></div><pre id="m_addons"></pre></div>
    </div>
  </div>
</div>

<div class="modalBack" id="masterListModalBack">
  <div class="modal" style="max-width: 800px;">
    <div class="row" style="justify-content:space-between;">
      <div style="font-weight:1000;font-size:20px;">Master Shopping List</div>
      <div class="row">
        <button class="btn" id="exportMasterCsvBtn">Download CSV</button>
        <button class="btn primary" onclick="window.print()">Print</button>
        <button class="btn ghost" id="closeMasterListModal">Close</button>
      </div>
    </div>
    <div class="hr"></div>
    <div class="card" style="box-shadow:none; background:rgba(0,0,0,.16);">
      <pre id="masterListOutput" style="font-size:16px; line-height:1.6;"></pre>
    </div>
  </div>
</div>

<script>
  const toast = (msg)=>{ const el = document.getElementById("toast"); el.textContent = msg; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"), 3500); };
  const qs = (k)=> document.getElementById(k);
  
  function switchTab(tab) {
    qs('tabContentOrders').style.display = tab === 'orders' ? 'block' : 'none';
    qs('tabContentCatalogue').style.display = tab === 'catalogue' ? 'block' : 'none';
    qs('tabBtnOrders').className = tab === 'orders' ? 'btn primary' : 'btn';
    qs('tabBtnCatalogue').className = tab === 'catalogue' ? 'btn primary' : 'btn';
    if(tab === 'catalogue') loadCatalogue();
  }

  // --- Orders Logic ---
  const rowsEl = qs("rows"); const countPill = qs("countPill"); let modalOrder = null;
  function buildQuery(){ const p = new URLSearchParams(); const q = qs("q").value.trim(); const state = qs("state").value.trim(); const runKey = qs("runKey").value.trim(); const zone = qs("zone").value.trim(); const town = qs("town").value.trim(); const flag = qs("flag").value.trim(); const unpaidFees = qs("unpaidFees").checked ? "1" : ""; const hold = qs("hold").checked ? "1" : ""; if(q) p.set("q", q); if(state) p.set("state", state); if(runKey) p.set("runKey", runKey); if(zone) p.set("zone", zone); if(town) p.set("town", town); if(flag) p.set("flag", flag); if(unpaidFees) p.set("unpaidFees", unpaidFees); if(hold) p.set("hold", hold); p.set("limit","200"); return p.toString(); }
  function esc(s){ return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"); }
  function money(n){ return Number(n||0).toFixed(2); }

  function render(items){
    const list = items || []; countPill.textContent = "Results: " + list.length;
    if(!list.length){ rowsEl.innerHTML = '<tr><td colspan="8" class="muted">No results.</td></tr>'; return; }
    rowsEl.innerHTML = list.map(o=>{
      const id = esc(o.orderId); const cust = esc(o.customer?.fullName || ""); const phone = esc(o.customer?.phone || ""); const email = esc(o.customer?.email || ""); const addr = esc((o.address?.streetAddress||"") + (o.address?.unit ? (" " + o.address.unit) : "") + ", " + (o.address?.town||"") + " " + (o.address?.postalCode||"")); const run = esc(o.runKey || ""); const rt = esc(o.runType || ""); const st = esc(o.status?.state || ""); const fees = money(o.pricingSnapshot?.totalFees || 0); const flags = []; const f = o.flags || {}; Object.keys(f).forEach(k=>{ if (f[k] === true) flags.push(k); }); const flagTxt = esc(flags.join(", "));
      return \`<tr><td><div style="font-weight:1000;">\${id}</div><div class="muted" style="font-size:12px;">\${email}</div></td><td><div style="font-weight:900;">\${cust}</div><div class="muted" style="font-size:12px;">\${phone}</div></td><td>\${addr}</td><td><span class="pill">\${rt}</span><div class="muted" style="font-size:12px;margin-top:4px;">\${run}</div></td><td><span class="pill">\${st}</span></td><td>$\${fees}</td><td><div class="muted" style="font-size:12px;">\${flagTxt || "—"}</div></td><td><button class="btn" data-open="\${id}">Open</button></td></tr>\`;
    }).join("");
    document.querySelectorAll("[data-open]").forEach(btn=>{ btn.addEventListener("click", ()=> openOrder(btn.getAttribute("data-open"))); });
  }

  async function search(){ rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Loading…</td></tr>'; try{ const r = await fetch("/api/admin/orders?" + buildQuery(), { credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Load failed"); render(d.items || []); } catch(e){ rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Error: ' + esc(e.message||e) + '</td></tr>'; } }

  function openModal(show){ qs("modalBack").style.display = show ? "flex" : "none"; }

  function buildAddonsText(o){
    const lines = []; const a = o.addOns || {};
    if (a.prescription?.requested) lines.push("Prescription: YES" + (a.prescription.pharmacyName ? " • " + a.prescription.pharmacyName : "") + (a.prescription.notes ? " • " + a.prescription.notes : ""));
    if (a.liquor?.requested) lines.push("Liquor: YES" + (a.liquor.storeName ? " • " + a.liquor.storeName : "") + (a.liquor.notes ? " • " + a.liquor.notes : ""));
    if (a.printing?.requested) lines.push("Printing: YES" + (a.printing.pages ? " • pages " + a.printing.pages : "") + (a.printing.notes ? " • " + a.printing.notes : ""));
    if (a.fastFood?.requested) lines.push("Fast food: YES" + (a.fastFood.restaurant ? " • " + a.fastFood.restaurant : "") + (a.fastFood.orderDetails ? " • " + a.fastFood.orderDetails : ""));
    if (a.parcel?.requested) lines.push("Parcel: YES" + (a.parcel.carrier ? " • " + a.parcel.carrier : "") + (a.parcel.details ? " • " + a.parcel.details : ""));
    if (a.bulky?.requested) lines.push("Bulky: YES" + (a.bulky.details ? " • " + a.bulky.details : ""));
    if (a.ride?.requested) lines.push("Ride: YES" + (a.ride.pickupAddress ? " • " + a.ride.pickupAddress : "") + (a.ride.preferredWindow ? " • " + a.ride.preferredWindow : "") + (a.ride.notes ? " • " + a.ride.notes : ""));
    if (Array.isArray(o.stores?.extra) && o.stores.extra.length) lines.push("Extra stores: " + o.stores.extra.join(", "));
    if (a.generalNotes) lines.push("General notes: " + a.generalNotes);
    if (o.deliveryMeta?.gateCode) lines.push("Gate code: " + o.deliveryMeta.gateCode);
    if (o.deliveryMeta?.buildingAccessNotes) lines.push("Building access: " + o.deliveryMeta.buildingAccessNotes);
    if (o.deliveryMeta?.parkingNotes) lines.push("Parking: " + o.deliveryMeta.parkingNotes);
    if (o.deliveryMeta?.receiptPreference) lines.push("Receipt pref: " + o.deliveryMeta.receiptPreference);
    if (o.deliveryMeta?.photoProofOk) lines.push("Photo proof OK: YES");
    return lines.length ? lines.join("\\n") : "—";
  }

  async function openOrder(orderId){
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(orderId), { credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Order load failed"); modalOrder = d.order;
      qs("m_orderId").textContent = modalOrder.orderId || "—"; qs("m_customer").textContent = modalOrder.customer?.fullName || "—"; qs("m_phone").textContent = modalOrder.customer?.phone || "—"; qs("m_altPhone").textContent = modalOrder.customer?.altPhone || "—"; qs("m_email").textContent = modalOrder.customer?.email || "—"; qs("m_dob").textContent = modalOrder.customer?.dob || "—";
      qs("m_addr").textContent = (modalOrder.address?.streetAddress || "") + (modalOrder.address?.unit ? (" " + modalOrder.address.unit) : "") + ((modalOrder.address?.town || modalOrder.address?.postalCode) ? ", " : "") + (modalOrder.address?.town || "") + (modalOrder.address?.postalCode ? " " + modalOrder.address.postalCode : "");
      qs("m_zone").textContent = modalOrder.address?.zone || "—"; qs("m_run").textContent = (modalOrder.runKey||"") + " (" + (modalOrder.runType||"") + ")"; qs("m_fees").textContent = "$" + money(modalOrder.pricingSnapshot?.totalFees || 0); qs("m_feesCurrent").textContent = modalOrder.payments?.fees?.status || "—"; qs("m_groceriesCurrent").textContent = modalOrder.payments?.groceries?.status || "—";
      qs("m_state").value = (modalOrder.status?.state || "submitted"); qs("m_stateNote").value = (modalOrder.status?.note || ""); qs("m_list").textContent = modalOrder.list?.groceryListText || "—"; qs("m_addons").textContent = buildAddonsText(modalOrder);
      qs("m_feesStatus").value = ""; qs("m_groceriesStatus").value = ""; qs("m_payNote").value = "";
      openModal(true);
    } catch(e){ toast(String(e.message||e)); }
  }

  async function saveStatus(){
    if(!modalOrder?.orderId) return; const state = qs("m_state").value; const note = qs("m_stateNote").value.trim();
    try{ const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/status", { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify({ state, note }) }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Save failed"); toast("Status saved ✅"); await openOrder(modalOrder.orderId); await search(); } catch(e){ toast(String(e.message||e)); }
  }

  async function savePayments(){
    if(!modalOrder?.orderId) return; const feesStatus = qs("m_feesStatus").value; const groceriesStatus = qs("m_groceriesStatus").value; const note = qs("m_payNote").value.trim();
    try{ const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/payments", { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify({ feesStatus, groceriesStatus, note }) }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Save failed"); toast("Payments saved ✅"); await openOrder(modalOrder.orderId); await search(); } catch(e){ toast(String(e.message||e)); }
  }

  async function cancelAdmin(){
    if(!modalOrder?.orderId) return; const ok = confirm("Cancel this order as admin?"); if(!ok) return; const reason = prompt("Reason (optional):", "Cancelled by admin") || "Cancelled by admin";
    try{ const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/cancel", { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify({ reason }) }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Cancel failed"); toast("Order cancelled ✅"); openModal(false); await search(); } catch(e){ toast(String(e.message||e)); }
  }

  async function deleteOrder(){
    if(!modalOrder?.orderId) return; const ok = confirm("Delete this order permanently? This cannot be undone."); if(!ok) return;
    try{ const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId), { method:"DELETE", credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Delete failed"); toast("Order deleted ✅"); openModal(false); await search(); } catch(e){ toast(String(e.message||e)); }
  }

  async function copyTrackingLink(){
    if(!modalOrder?.orderId) return;
    try{ const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/tracking-link", { credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Link failed"); await navigator.clipboard.writeText(d.url || ""); toast("Tracking link copied ✅"); } catch(e){ toast(String(e.message||e)); }
  }

  function clearFilters(){ qs("q").value=""; qs("state").value=""; qs("runKey").value=""; qs("zone").value=""; qs("town").value=""; qs("flag").value=""; qs("unpaidFees").checked=false; qs("hold").checked=false; }
  qs("searchBtn").addEventListener("click", search); qs("refreshBtn").addEventListener("click", search); qs("clearBtn").addEventListener("click", ()=>{ clearFilters(); search(); });
  
  qs("exportBtn").addEventListener("click", ()=>{ const rk = qs("toolRunKey").value.trim(); if(!rk) return toast("Enter runKey to export"); window.location.href = "/api/admin/routific/export-csv?runKey=" + encodeURIComponent(rk); });
  
  // Master Shopping List logic
  let cachedMasterListData = null;

  qs("masterListBtn").addEventListener("click", async () => {
    const rk = qs("toolRunKey").value.trim();
    if(!rk) return toast("Enter runKey to generate Master List");
    
    try {
      const r = await fetch("/api/admin/runs/" + encodeURIComponent(rk) + "/master-list", { credentials:"include" });
      const d = await r.json();
      if (!r.ok || d.ok === false) throw new Error(d.error || "Master List failed");
      
      cachedMasterListData = d; // Save data globally so the CSV button can use it
      
      let out = "MASTER SHOPPING LIST: " + rk + "\\n";
      out += "==============================================\\n\\n";
      
      if (d.items.length === 0) {
        out += "No items found in active orders for this run.\\n\\n";
      } else {
        d.items.forEach(i => {
          out += "[  ] " + i.count + "x  " + i.name + "\\n";
        });
      }
      
      if (d.extraStops && d.extraStops.length > 0) {
        out += "\\nEXTRA STORE STOPS:\\n";
        out += "==============================================\\n";
        d.extraStops.forEach(s => {
          out += "• " + s + "\\n";
        });
      }
      
      qs("masterListOutput").textContent = out;
      qs("masterListModalBack").style.display = "flex";
    } catch(e) {
      toast(String(e.message||e));
    }
  });

  qs("exportMasterCsvBtn").addEventListener("click", () => {
    if (!cachedMasterListData) return;
    
    let csv = "Quantity,Item\\n";
    
    // Add grocery items
    cachedMasterListData.items.forEach(i => {
      const safeName = i.name.replace(/"/g, '""');
      csv += \`"\${i.count}","\${safeName}"\\n\`;
    });
    
    // Add extra stops
    if (cachedMasterListData.extraStops && cachedMasterListData.extraStops.length > 0) {
      csv += "\\nExtra Stops\\n";
      cachedMasterListData.extraStops.forEach(s => {
        const safeStop = s.replace(/"/g, '""');
        csv += \`"","\${safeStop}"\\n\`;
      });
    }
    
    // Trigger download
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "master_list_" + cachedMasterListData.runKey + ".csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  qs("closeMasterListModal").addEventListener("click", () => { qs("masterListModalBack").style.display = "none"; });
  qs("masterListModalBack").addEventListener("click", (e) => { if(e.target.id === "masterListModalBack") qs("masterListModalBack").style.display = "none"; });

  qs("closeModal").addEventListener("click", ()=> openModal(false)); qs("modalBack").addEventListener("click", (e)=>{ if(e.target.id==="modalBack") openModal(false); });
  qs("m_saveState").addEventListener("click", saveStatus); qs("m_savePay").addEventListener("click", savePayments); qs("m_cancelAdmin").addEventListener("click", cancelAdmin); qs("m_deleteOrder").addEventListener("click", deleteOrder); qs("m_trackingLink").addEventListener("click", copyTrackingLink);
  search();

  // --- Catalogue Logic ---
  async function loadCatalogue() {
    qs('catRows').innerHTML = '<tr><td colspan="4" class="muted">Loading...</td></tr>';
    try {
      const r = await fetch('/api/admin/catalogue', { credentials: 'include' });
      const d = await r.json();
      if(!d.ok) throw new Error("Failed to load");
      const items = d.items || [];
      qs('catCountPill').textContent = "Items: " + items.length;
      if(!items.length) {
        qs('catRows').innerHTML = '<tr><td colspan="4" class="muted">No items in catalogue.</td></tr>';
        return;
      }
      qs('catRows').innerHTML = items.map(i => {
        return \`<tr>
          <td><div style="font-weight:900;">\${esc(i.name)}</div></td>
          <td>\${esc(i.category)}</td>
          <td>$\${money(i.estimatedPrice)}</td>
          <td><button class="btn ghost small" onclick="deleteCatItem('\${i._id}')">Delete</button></td>
        </tr>\`;
      }).join('');
    } catch(e) {
      qs('catRows').innerHTML = '<tr><td colspan="4" class="muted">Error loading catalogue.</td></tr>';
    }
  }

  qs('addCatBtn').addEventListener('click', async () => {
    const name = qs('catName').value.trim();
    const category = qs('catCategory').value.trim();
    const estimatedPrice = qs('catPrice').value.trim();
    if(!name) return toast("Name is required");
    try {
      const r = await fetch('/api/admin/catalogue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name, category, estimatedPrice })
      });
      const d = await r.json();
      if(!d.ok) throw new Error(d.error || "Add failed");
      toast("Item added ✅");
      qs('catName').value = ''; qs('catCategory').value = ''; qs('catPrice').value = '';
      loadCatalogue();
    } catch(e) { toast(String(e.message || e)); }
  });

  qs('seedCatBtn').addEventListener('click', async () => {
    if(!confirm("Add standard default grocery items to the catalogue?")) return;
    try {
      const r = await fetch('/api/admin/catalogue/seed', { method: 'POST', credentials: 'include' });
      const d = await r.json();
      if(!d.ok) throw new Error(d.error || "Seed failed");
      toast("Defaults added ✅");
      loadCatalogue();
    } catch(e) { toast(String(e.message || e)); }
  });

  async function deleteCatItem(id) {
    if(!confirm("Delete this item?")) return;
    try {
      const r = await fetch('/api/admin/catalogue/' + id, { method: 'DELETE', credentials: 'include' });
      if(!r.ok) throw new Error("Delete failed");
      toast("Item deleted ✅");
      loadCatalogue();
    } catch(e) { toast(String(e)); }
  }

</script>
</body>
</html>`);
});

// =========================
// EXPORT CSV
// =========================
app.get("/api/admin/routific/export-csv", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.query.runKey || "").trim();
    if (!runKey) return res.status(400).send("Missing runKey");
    const orders = await Order.find({ runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } }).sort({ createdAt: 1 }).lean();
    const header = ["order_id","name","address","phone","email","notes","duration_seconds"];
    const rows = orders.map(o => {
      const name = o.customer?.fullName || ""; const phone = o.customer?.phone || ""; const email = o.customer?.email || "";
      const address = `${o.address?.streetAddress || ""}${o.address?.unit ? (" " + o.address.unit) : ""}, ${o.address?.town || ""}, ON, ${o.address?.postalCode || ""}, Canada`.replace(/\s+/g, " ").trim();
      const notes = [`TGR ${o.orderId}`, `Zone ${o.address?.zone || ""}`, o.preferences?.dropoffPref ? `Drop-off: ${o.preferences.dropoffPref}` : "", o.preferences?.subsPref ? `Subs: ${o.preferences.subsPref}` : "", o.stores?.primary ? `Store: ${o.stores.primary}` : "", (o.stores?.extra || []).length ? `Extra: ${(o.stores.extra || []).join(", ")}` : ""].filter(Boolean).join(" | ");
      return [o.orderId, name, address, phone, email, notes, "360"].map(csvEscape).join(",");
    });
    const csv = header.join(",") + "\n" + rows.join("\n") + "\n";
    res.setHeader("Content-Type", "text/csv; charset=utf-8"); res.setHeader("Content-Disposition", `attachment; filename="routific_${runKey}_deliveries.csv"`); res.send(csv);
  } catch (e) { res.status(500).send(String(e)); }
});

// =========================
// TRACKING CONTROL PAGE
// =========================
app.get("/admin/tracking-control", requireLogin, requireAdmin, async (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="en-CA"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TGR Tracking</title><style>:root{--bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14); --text:#fff; --muted:rgba(255,255,255,.75); --red:#e3342f; --red2:#ff4a44; --radius:14px;} body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;} .wrap{max-width:900px;margin:0 auto;padding:16px;} .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;} .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;} .btn{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-weight:900;border-radius:999px;padding:10px 14px;cursor:pointer;text-decoration:none;white-space:nowrap;} .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);} .btn.ghost{background:transparent;} .muted{color:var(--muted);} select,input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.25);color:#fff;font-size:16px;} .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;} .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;} .toast.show{display:block;} .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}</style></head><body><div class="wrap"><div class="card"><div class="row" style="justify-content:space-between;"><div><div style="font-weight:1000;font-size:22px;">Tracking Control</div></div><div class="row"><a class="btn ghost" href="/admin">Admin</a></div></div><div class="toast" id="toast"></div><div class="hr"></div><div class="row"><div style="flex:1 1 380px;"><label class="muted" style="font-weight:900;">Select run</label><select id="runSel"><option value="">Loading…</option></select><div class="muted" id="runInfo" style="margin-top:8px;font-size:13px;"></div></div><div style="flex:1 1 240px;"><label class="muted" style="font-weight:900;">GPS interval</label><input id="interval" type="number" min="500" step="100" value="1500"/></div></div><div class="hr"></div><div class="row"><button class="btn" id="enableBtn">Start tracking (enable run)</button><button class="btn" id="disableBtn">Stop tracking (disable run)</button><span class="pill" id="enabledState">—</span></div><div class="hr"></div><div class="row"><button class="btn primary" id="startGps">Start GPS broadcast</button><button class="btn" id="stopGps">Stop GPS broadcast</button><span class="pill" id="gpsState">GPS: idle</span></div><div class="muted" id="lastSend" style="margin-top:10px;font-size:13px;">Last send: —</div><div class="muted" id="err" style="margin-top:6px;font-size:13px;"></div></div></div><script>const toast = (msg)=>{const el = document.getElementById("toast"); el.textContent = msg; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"), 3500);}; const runSel = document.getElementById("runSel"); const runInfo = document.getElementById("runInfo"); const enabledState = document.getElementById("enabledState"); const gpsState = document.getElementById("gpsState"); const lastSend = document.getElementById("lastSend"); const err = document.getElementById("err"); const intervalEl = document.getElementById("interval"); let runs = null; let watchId = null; let lastPostAt = 0; async function loadRuns(){const r = await fetch("/api/runs/active", { credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Runs unavailable"); runs = d.runs || null; runSel.innerHTML = '<option value="">Select…</option>'; const L = runs.local; const O = runs.owen; if (L?.runKey){const o = document.createElement("option"); o.value = L.runKey; o.textContent = "Local: " + L.runKey; runSel.appendChild(o);} if (O?.runKey){const o = document.createElement("option"); o.value = O.runKey; o.textContent = "Owen: " + O.runKey; runSel.appendChild(o);}} function getRunByKey(k){if (!runs) return null; if (runs.local?.runKey === k) return runs.local; if (runs.owen?.runKey === k) return runs.owen; return null;} function updateRunInfo(){const k = runSel.value; const r = getRunByKey(k); if(!r){ runInfo.textContent = ""; enabledState.textContent = "—"; return; } runInfo.textContent = "Opens: " + r.opensAtLocal + " • Cutoff: " + r.cutoffAtLocal + " • Slots: " + r.slotsRemaining; enabledState.textContent = r.isOpen ? "Orders open" : "Orders closed";} runSel.addEventListener("change", updateRunInfo); async function enableTracking(){const k = runSel.value; if(!k) return toast("Select a runKey"); const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/start", { method:"POST", credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) return toast(d.error || "Enable failed"); toast("Tracking enabled for " + k);} async function disableTracking(){const k = runSel.value; if(!k) return toast("Select a runKey"); const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/stop", { method:"POST", credentials:"include" }); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) return toast(d.error || "Disable failed"); toast("Tracking disabled for " + k);} async function postFix(pos){const k = runSel.value; if(!k) return; const ms = Math.max(500, Number(intervalEl.value || 1500)); const now = Date.now(); if ((now - lastPostAt) < ms) return; lastPostAt = now; const c = pos.coords || {}; const body = {lat: c.latitude, lng: c.longitude, heading: Number.isFinite(c.heading) ? c.heading : null, speed: Number.isFinite(c.speed) ? c.speed : null, accuracy: Number.isFinite(c.accuracy) ? c.accuracy : null,}; try{const r = await fetch("/api/admin/tracking/" + encodeURIComponent(k) + "/update", {method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify(body),}); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) throw new Error(d.error || "Update failed"); gpsState.textContent = "GPS: sending ✅"; lastSend.textContent = "Last send: " + new Date().toLocaleString() + " • acc " + Math.round(Number(body.accuracy||0)) + "m"; err.textContent = "";} catch(e){gpsState.textContent = "GPS: error"; err.textContent = String(e.message || e);}} function startGps(){if(!navigator.geolocation) return toast("Geolocation not supported on this device"); const k = runSel.value; if(!k) return toast("Select a runKey first"); if (watchId) navigator.geolocation.clearWatch(watchId); watchId = navigator.geolocation.watchPosition(postFix, (e)=>{ gpsState.textContent = "GPS: error"; err.textContent = e.message || "GPS error"; }, { enableHighAccuracy:true, maximumAge:1000, timeout:10000 }); toast("GPS broadcast started"); gpsState.textContent = "GPS: starting…";} function stopGps(){if (watchId) navigator.geolocation.clearWatch(watchId); watchId = null; gpsState.textContent = "GPS: idle"; toast("GPS broadcast stopped");} document.getElementById("enableBtn").addEventListener("click", enableTracking); document.getElementById("disableBtn").addEventListener("click", disableTracking); document.getElementById("startGps").addEventListener("click", startGps); document.getElementById("stopGps").addEventListener("click", stopGps); loadRuns().then(updateRunInfo).catch(e=>toast(String(e.message||e)));</script></body></html>`);
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