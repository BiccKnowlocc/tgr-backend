// ======= server.js (FULL FILE) — TGR backend =======
// Express + MongoDB + Google OAuth + Runs + Estimator + Orders + Admin UI
// Square: pay links + Square webhook (auto mark paid by Payment Link ID)
// Postmark: sending + webhooks
//
// NEW IN THIS VERSION:
// - Ops email to orders@ on every new order (full details + list + add-ons)
// - Customer confirmation email stays (short)
// - Slots count per-run and only ACTIVE orders count toward slots
// - Admin cancel/delete releases slot
// - Customer self-cancel with signed token before cutoff

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const fs = require("fs");
const crypto = require("crypto");

const MongoStorePkg = require("connect-mongo");
const MongoStore = MongoStorePkg.default || MongoStorePkg;

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const { Client, Environment, WebhooksHelper } = require("square");
const postmark = require("postmark");

let nanoid = null;
try { nanoid = require("nanoid").nanoid; } catch {}

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
const CANCEL_TOKEN_SECRET = process.env.CANCEL_TOKEN_SECRET || SESSION_SECRET;

const TZ = process.env.TZ || "America/Toronto";
const NODE_ENV = process.env.NODE_ENV || "production";

const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://tobermorygroceryrun.ca";

// Google OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

// Admin allowlist
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// CORS allowlist
const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:8888",
  "http://localhost:3000",
];

// Uploads
const UPLOAD_DIR = process.env.UPLOAD_DIR || "uploads";

// Postmark
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || "";
const POSTMARK_MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || "outbound";
const EMAIL_FROM = process.env.EMAIL_FROM || "orders@tobermorygroceryrun.ca";
const EMAIL_REPLY_TO = process.env.EMAIL_REPLY_TO || EMAIL_FROM;

// NEW: ops mailbox for internal notifications
const OPS_EMAIL_TO = process.env.OPS_EMAIL_TO || "orders@tobermorygroceryrun.ca";

// Postmark webhook basic auth (optional)
const POSTMARK_WEBHOOK_USERNAME = process.env.POSTMARK_WEBHOOK_USERNAME || "";
const POSTMARK_WEBHOOK_PASSWORD = process.env.POSTMARK_WEBHOOK_PASSWORD || "";

// Square webhook
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";
const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL =
  process.env.SQUARE_WEBHOOK_NOTIFICATION_URL ||
  "https://api.tobermorygroceryrun.ca/webhooks/square";

const SQUARE_PAY_FEES_SLUG = process.env.SQUARE_PAY_FEES_SLUG || "r92W6XGs";
const SQUARE_PAY_GROCERIES_SLUG = process.env.SQUARE_PAY_GROCERIES_SLUG || "R0hfr7x8";

const SQUARE_PAY_LINKS = {
  fees: process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs",
  groceries: process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8",
};

const SQUARE_MEMBERSHIP_LINKS = {
  standard: process.env.SQUARE_LINK_STANDARD || "https://square.link/u/iaziCZjG",
  route: process.env.SQUARE_LINK_ROUTE || "https://square.link/u/P5ROgqyp",
  access: process.env.SQUARE_LINK_ACCESS || "https://square.link/u/lHtHtvqG",
  accesspro: process.env.SQUARE_LINK_ACCESSPRO || "https://square.link/u/S0Y5Fysa",
};

// =========================
// UTIL
// =========================
function makeReqId() {
  if (nanoid) return nanoid(12);
  return Math.random().toString(16).slice(2) + Date.now().toString(16);
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function yn(v) {
  return v === true || String(v || "").toLowerCase() === "yes";
}

function nowTz() {
  return dayjs().tz(TZ);
}

function fmtLocal(d) {
  if (!d) return "";
  return dayjs(d).tz(TZ).format("ddd MMM D, h:mma");
}

function isAdminEmail(email) {
  const e = String(email || "").toLowerCase().trim();
  if (!e) return false;
  if (!ADMIN_EMAILS.length) return true;
  return ADMIN_EMAILS.includes(e);
}

function squareClient() {
  return new Client({
    accessToken: SQUARE_ACCESS_TOKEN,
    environment: Environment.Production,
  });
}

function extractLastName(fullName) {
  const parts = String(fullName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (parts.length === 0) return "";
  return parts[parts.length - 1];
}

function base64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
function base64urlDecodeToString(b64url) {
  const pad = b64url.length % 4 ? "=".repeat(4 - (b64url.length % 4)) : "";
  const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/") + pad;
  return Buffer.from(b64, "base64").toString("utf8");
}

function signCancelToken(orderId, expMs) {
  const payload = `${orderId}.${String(expMs)}`;
  const sig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payload).digest();
  const token = `${base64urlEncode(payload)}.${base64urlEncode(sig)}`;
  return token;
}

function verifyCancelToken(orderId, token) {
  try {
    const t = String(token || "").trim();
    const parts = t.split(".");
    if (parts.length !== 2) return { ok: false, error: "Bad token" };

    const payloadStr = base64urlDecodeToString(parts[0]);
    const sigB64 = parts[1];

    const [oid, expStr] = payloadStr.split(".");
    const expMs = Number(expStr);

    if (!oid || oid !== orderId) return { ok: false, error: "Token order mismatch" };
    if (!Number.isFinite(expMs) || expMs <= 0) return { ok: false, error: "Bad expiry" };

    const expectedSig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payloadStr).digest();
    const expectedB64 = base64urlEncode(expectedSig);

    const a = Buffer.from(sigB64);
    const b = Buffer.from(expectedB64);
    if (a.length !== b.length) return { ok: false, error: "Bad signature" };
    if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "Bad signature" };

    return { ok: true, expMs };
  } catch {
    return { ok: false, error: "Bad token" };
  }
}

// =========================
// APP + MIDDLEWARE
// =========================
const app = express();
app.set("trust proxy", 1);

app.use((req, res, next) => {
  req.id = req.get("x-request-id") || makeReqId();
  res.setHeader("x-request-id", req.id);
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(compression());

app.use(
  morgan(
    ":date[iso] :remote-addr :method :url :status :res[content-length] - :response-time ms rid=:req[x-request-id]",
    { skip: () => NODE_ENV === "test" }
  )
);

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 240,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
});

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 900,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
  })
);

app.use(
  express.json({
    limit: "6mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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
      { clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: GOOGLE_CALLBACK_URL },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || "";
          const normalized = String(email).toLowerCase().trim();
          if (!normalized) return done(null, false);

          const update = {
            googleId: profile.id,
            email: normalized,
            name: profile.displayName || "",
            photo: (profile.photos && profile.photos[0] && profile.photos[0].value) || "",
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
                profile: { version: 1, complete: false, defaultId: "", addresses: [] },
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
// UPLOADS
// =========================
if (!fs.existsSync(UPLOAD_DIR)) {
  try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch {}
}

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 15 * 1024 * 1024 },
});

function safeUnlink(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, () => {});
}

// =========================
// PRICING BASELINE (estimator snapshot)
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
  return PRICING.addOns.printingBase + first * PRICING.addOns.printingFirst10 + rest * PRICING.addOns.printingAfter10;
}

function membershipDiscounts(tier, applyPerkYes) {
  if (!tier || !applyPerkYes) return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0 };
  if (tier === "standard") return { serviceOff: 0, zoneOff: 10, freeAddonUpTo: 10 };
  if (tier === "route") return { serviceOff: 5, zoneOff: 10, freeAddonUpTo: 10 };
  if (tier === "access") return { serviceOff: 8, zoneOff: 10, freeAddonUpTo: 10 };
  if (tier === "accesspro") return { serviceOff: 10, zoneOff: 0, freeAddonUpTo: 0 };
  return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0 };
}

// =========================
// DB MODELS (server-local)
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

    customerName: { type: String, default: "", index: true },
    customerLastName: { type: String, default: "", index: true },
    customerEmail: { type: String, default: "", index: true },
    customerPhone: { type: String, default: "", index: true },

    runKey: { type: String, required: true, index: true },
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

    payments: {
      fees: {
        status: { type: String, enum: ["unpaid", "pending", "paid"], default: "unpaid" },
        paidAt: { type: Date, default: null },
        squarePaymentId: { type: String, default: "" },
        note: { type: String, default: "" },
      },
      groceries: {
        status: { type: String, enum: ["unpaid", "pending", "paid"], default: "unpaid" },
        paidAt: { type: Date, default: null },
        squarePaymentId: { type: String, default: "" },
        note: { type: String, default: "" },
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
          note: { type: String, default: "" },
          at: { type: Date, default: Date.now },
          by: { type: String, default: "system" },
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

const WebhookEventSchema = new mongoose.Schema(
  { eventId: { type: String, unique: true, index: true }, type: { type: String, default: "" } },
  { timestamps: true }
);

const PaymentLinkCacheSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, index: true }, // "fees" | "groceries"
    slug: { type: String, default: "" },
    paymentLinkId: { type: String, default: "" },
    paymentLinkUrl: { type: String, default: "" },
    refreshedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const WebhookEvent = mongoose.model("WebhookEvent", WebhookEventSchema);
const PaymentLinkCache = mongoose.model("PaymentLinkCache", PaymentLinkCacheSchema);

// =========================
// PROFILE COMPLETION
// =========================
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
    return !!street && !!town && !!zone;
  });

  const consentsOk = p.consentTerms === true && p.consentPrivacy === true;
  return !!fullName && !!phone && !!contactPref && contactAuth && hasAddress && consentsOk;
}

// =========================
// RUN CALENDAR + AGG
// =========================
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
  if (type === "local")
    return { minOrders: 6, minFees: 200, minLogic: "OR", minimumText: "Minimum: 6 orders OR $200 booked fees" };
  return { minOrders: 6, minFees: 300, minLogic: "AND", minimumText: "Minimum: 6 orders AND $300 booked fees" };
}

function meetsMinimums(run) {
  if (run.minLogic === "AND") return run.bookedOrdersCount >= run.minOrders && run.bookedFeesTotal >= run.minFees;
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
      !run.lastRecalcAt || dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(60, "second").toDate());

    if (needsRecalc) {
      const agg = await Order.aggregate([
        { $match: { runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } } },
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
// EMAIL (Postmark)
// =========================
let postmarkClient = null;

function initEmail() {
  if (!POSTMARK_SERVER_TOKEN) return;
  postmarkClient = new postmark.ServerClient(POSTMARK_SERVER_TOKEN);
}

function canEmail() {
  return !!(POSTMARK_SERVER_TOKEN && EMAIL_FROM && postmarkClient);
}

async function sendEmail({ to, subject, html, text, tag, metadata, messageStream }) {
  if (!canEmail()) return { ok: false, skipped: true, reason: "email_not_configured" };
  const recipient = String(to || "").trim().toLowerCase();
  if (!recipient) return { ok: false, skipped: true, reason: "missing_to" };

  const payload = {
    From: EMAIL_FROM,
    To: recipient,
    ReplyTo: EMAIL_REPLY_TO || undefined,
    Subject: subject,
    HtmlBody: html,
    TextBody: text || undefined,
    MessageStream: messageStream || POSTMARK_MESSAGE_STREAM,
    Tag: tag || undefined,
    Metadata: metadata || undefined,
  };

  const r = await postmarkClient.sendEmail(payload);
  return { ok: true, messageId: r?.MessageID || "" };
}

function emailShell(title, bodyHtml) {
  return `
  <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b0b;padding:18px;">
    <div style="max-width:760px;margin:0 auto;background:#111;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:18px;color:#fff;">
      <div style="font-size:20px;font-weight:900;margin-bottom:10px;">${escapeHtml(title)}</div>
      <div style="color:rgba(255,255,255,.86);font-size:15px;line-height:1.55;">${bodyHtml}</div>
      <div style="margin-top:14px;color:rgba(255,255,255,.65);font-size:12px;">
        Tobermory Grocery Run • ${escapeHtml(PUBLIC_SITE_URL)}
      </div>
    </div>
  </div>`;
}

function orderReceivedCustomerEmail(order, cancelUntilLocal) {
  const orderId = escapeHtml(order.orderId);
  const trackUrl = `${PUBLIC_SITE_URL}/?tab=status`;

  const body = `
    <div style="padding:12px;border:1px solid rgba(227,52,47,.35);background:rgba(227,52,47,.12);border-radius:12px;margin:12px 0;">
      <div style="font-weight:900;font-size:16px;">Your Order ID:</div>
      <div style="font-weight:1000;font-size:24px;letter-spacing:.5px;margin-top:4px;">${orderId}</div>
      <div style="margin-top:8px;color:rgba(255,255,255,.9);">Put <strong>${orderId}</strong> in Square payment notes.</div>
    </div>
    <div><strong>Track:</strong> <a href="${trackUrl}" style="color:#fff;text-decoration:underline;">${escapeHtml(trackUrl)}</a></div>
    <div style="margin-top:10px;"><strong>Cancel window:</strong> before <strong>${escapeHtml(cancelUntilLocal)}</strong> (see Live Status).</div>
  `;
  return emailShell("Order received", body);
}

function orderReceivedOpsEmail(order, payload, cancelUntilLocal) {
  const o = order;
  const addr = o.address || {};
  const stores = o.stores || {};
  const extra = (stores.extra || []).map(escapeHtml).join(", ") || "—";

  const fees = (o.pricingSnapshot && typeof o.pricingSnapshot.totalFees === "number")
    ? o.pricingSnapshot.totalFees.toFixed(2)
    : "0.00";

  const attach = o.list?.attachment
    ? `Yes (${escapeHtml(o.list.attachment.originalName || "")}, ${escapeHtml(o.list.attachment.mimeType || "")}, ${escapeHtml(String(o.list.attachment.size || 0))} bytes)`
    : "No";

  const body = `
    <div style="padding:12px;border:1px solid rgba(227,52,47,.35);background:rgba(227,52,47,.12);border-radius:12px;margin:12px 0;">
      <div style="font-weight:900;font-size:16px;">New Order:</div>
      <div style="font-weight:1000;font-size:26px;letter-spacing:.5px;margin-top:4px;">${escapeHtml(o.orderId)}</div>
      <div style="margin-top:6px;color:rgba(255,255,255,.9);">
        Run: <strong>${escapeHtml(o.runType)}</strong> • ${escapeHtml(o.runKey)} • Cutoff: <strong>${escapeHtml(cancelUntilLocal)}</strong>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
      <div style="padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
        <div style="font-weight:900;margin-bottom:6px;">Customer</div>
        <div><strong>Name:</strong> ${escapeHtml(o.customerName || o.customer?.fullName || "")}</div>
        <div><strong>Email:</strong> ${escapeHtml(o.customerEmail || o.customer?.email || "")}</div>
        <div><strong>Phone:</strong> ${escapeHtml(o.customerPhone || o.customer?.phone || "")}</div>
      </div>

      <div style="padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
        <div style="font-weight:900;margin-bottom:6px;">Address</div>
        <div><strong>Town:</strong> ${escapeHtml(addr.town || "")}</div>
        <div><strong>Zone:</strong> ${escapeHtml(addr.zone || "")}</div>
        <div><strong>Street:</strong> ${escapeHtml(addr.streetAddress || "")}</div>
      </div>
    </div>

    <div style="margin-top:10px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
      <div style="font-weight:900;margin-bottom:6px;">Stores</div>
      <div><strong>Primary:</strong> ${escapeHtml(stores.primary || "")}</div>
      <div><strong>Extra stops:</strong> ${extra}</div>
    </div>

    <div style="margin-top:10px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
      <div style="font-weight:900;margin-bottom:6px;">Preferences</div>
      <div><strong>Dropoff:</strong> ${escapeHtml(o.preferences?.dropoffPref || "")}</div>
      <div><strong>Subs:</strong> ${escapeHtml(o.preferences?.subsPref || "")}</div>
      <div><strong>Contact:</strong> ${escapeHtml(o.preferences?.contactPref || "")}</div>
    </div>

    <div style="margin-top:10px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
      <div style="font-weight:900;margin-bottom:6px;">Fees snapshot</div>
      <div><strong>Total fees:</strong> $${escapeHtml(fees)}</div>
      <div style="color:rgba(255,255,255,.78);font-size:13px;margin-top:6px;">
        Service ${escapeHtml(String(o.pricingSnapshot?.serviceFee ?? ""))} • Zone ${escapeHtml(String(o.pricingSnapshot?.zoneFee ?? ""))} • Run ${escapeHtml(String(o.pricingSnapshot?.runFee ?? ""))} • Add-ons ${escapeHtml(String(o.pricingSnapshot?.addOnsFees ?? ""))} • Surcharges ${escapeHtml(String(o.pricingSnapshot?.surcharges ?? ""))} • Discount ${escapeHtml(String(o.pricingSnapshot?.discount ?? ""))}
      </div>
    </div>

    <div style="margin-top:10px;padding:12px;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(0,0,0,.22);">
      <div style="font-weight:900;margin-bottom:6px;">List</div>
      <div style="white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:13px;color:rgba(255,255,255,.92);">
${escapeHtml(o.list?.groceryListText || "")}
      </div>
      <div style="margin-top:10px;color:rgba(255,255,255,.80);"><strong>Attachment:</strong> ${attach}</div>
    </div>

    <div style="margin-top:12px;color:rgba(255,255,255,.72);font-size:12px;">
      (Internal) Source payload keys present: ${escapeHtml(Object.keys(payload||{}).join(", "))}
    </div>
  `;

  return emailShell("NEW ORDER (OPS)", body);
}

// =========================
// PAYMENT LINK RESOLUTION (Square listPaymentLinks → map slug → paymentLinkId)
// =========================
const paymentLinkState = {
  fees: { slug: SQUARE_PAY_FEES_SLUG, paymentLinkId: "", url: "" },
  groceries: { slug: SQUARE_PAY_GROCERIES_SLUG, paymentLinkId: "", url: "" },
  lastRefreshAt: null,
};

function slugInUrl(url, slug) {
  return typeof url === "string" && url.toLowerCase().includes(`/u/${String(slug).toLowerCase()}`);
}

async function refreshPaymentLinkIds() {
  if (!SQUARE_ACCESS_TOKEN) return;

  const client = squareClient();
  let cursor = undefined;
  const found = { fees: null, groceries: null };

  for (let i = 0; i < 15; i++) {
    const resp = await client.paymentLinksApi.listPaymentLinks(cursor);
    const list = resp?.result?.paymentLinks || [];
    for (const pl of list) {
      const url = pl?.url || "";
      if (!found.fees && slugInUrl(url, paymentLinkState.fees.slug)) found.fees = pl;
      if (!found.groceries && slugInUrl(url, paymentLinkState.groceries.slug)) found.groceries = pl;
    }
    cursor = resp?.result?.cursor;
    if (!cursor) break;
  }

  async function upsert(key, obj) {
    if (!obj) return;
    await PaymentLinkCache.updateOne(
      { key },
      {
        $set: {
          key,
          slug: key === "fees" ? paymentLinkState.fees.slug : paymentLinkState.groceries.slug,
          paymentLinkId: String(obj.id || ""),
          paymentLinkUrl: String(obj.url || ""),
          refreshedAt: new Date(),
        },
      },
      { upsert: true }
    );
  }

  if (found.fees) {
    paymentLinkState.fees.paymentLinkId = String(found.fees.id || "");
    paymentLinkState.fees.url = String(found.fees.url || "");
    await upsert("fees", found.fees);
  }
  if (found.groceries) {
    paymentLinkState.groceries.paymentLinkId = String(found.groceries.id || "");
    paymentLinkState.groceries.url = String(found.groceries.url || "");
    await upsert("groceries", found.groceries);
  }

  paymentLinkState.lastRefreshAt = new Date();
}

async function loadPaymentLinkIdsFromDb() {
  const fees = await PaymentLinkCache.findOne({ key: "fees" }).lean();
  const groceries = await PaymentLinkCache.findOne({ key: "groceries" }).lean();
  if (fees?.paymentLinkId) {
    paymentLinkState.fees.paymentLinkId = fees.paymentLinkId;
    paymentLinkState.fees.url = fees.paymentLinkUrl || "";
  }
  if (groceries?.paymentLinkId) {
    paymentLinkState.groceries.paymentLinkId = groceries.paymentLinkId;
    paymentLinkState.groceries.url = groceries.paymentLinkUrl || "";
  }
}

// =========================
// SQUARE WEBHOOK HELPERS
// =========================
function extractOrderIdFromNote(note) {
  const m = String(note || "").match(/TGR-\d{5}/i);
  return m ? m[0].toUpperCase() : "";
}

function tryExtractPaymentLinkId(evt) {
  const candidates = [
    evt?.data?.object?.payment?.payment_link_id,
    evt?.data?.object?.payment?.source_type === "PAYMENT_LINK" ? evt?.data?.object?.payment?.source_id : undefined,
    evt?.data?.object?.payment?.source_id,
    evt?.data?.object?.order?.source?.id,
    evt?.data?.object?.order?.payment_link_id,
  ];
  for (const c of candidates) {
    const v = String(c || "").trim();
    if (v) return v;
  }
  return "";
}

function tryExtractPaymentId(evt) {
  const candidates = [
    evt?.data?.object?.payment?.id,
    evt?.data?.object?.payment?.payment_id,
    evt?.data?.object?.refund?.payment_id,
    evt?.data?.object?.payment_refund?.payment_id,
  ];
  for (const c of candidates) {
    const v = String(c || "").trim();
    if (v) return v;
  }
  return "";
}

function tryExtractNote(evt) {
  const candidates = [evt?.data?.object?.payment?.note, evt?.data?.object?.order?.note];
  for (const c of candidates) {
    const v = String(c || "").trim();
    if (v) return v;
  }
  return "";
}

async function retrievePayment(paymentId) {
  if (!SQUARE_ACCESS_TOKEN || !paymentId) return null;
  const client = squareClient();
  const resp = await client.paymentsApi.getPayment(paymentId);
  return resp?.result?.payment || null;
}

function pickBucketByPaymentLinkId(paymentLinkId) {
  const id = String(paymentLinkId || "").trim();
  if (!id) return "";
  if (id === paymentLinkState.fees.paymentLinkId) return "fees";
  if (id === paymentLinkState.groceries.paymentLinkId) return "groceries";
  return "";
}

// =========================
// GUARDS
// =========================
function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "Sign-in required." });
  next();
}

function requireAdmin(req, res, next) {
  const email = String(req.user?.email || "").toLowerCase();
  if (!email || !isAdminEmail(email)) return res.status(403).send("Admin access required.");
  next();
}

function requireProfileComplete(req, res, next) {
  if (!isProfileComplete(req.user?.profile || {})) {
    return res.status(403).json({ ok: false, error: "Account setup required. Please complete your profile." });
  }
  next();
}

// =========================
// AUTH ROUTES
// =========================
app.get("/auth/google", authLimiter, (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
    return res.status(500).send("Google auth is not configured on this server.");
  }
  req.session.returnTo = String(req.query.returnTo || (PUBLIC_SITE_URL + "/")).trim();
  return passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  authLimiter,
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

    const newProfile = {
      version: 1,
      fullName: String(b.fullName || "").trim(),
      preferredName: String(b.preferredName || "").trim(),
      phone: String(b.phone || "").trim(),
      altPhone: String(b.altPhone || "").trim(),
      contactPref: String(b.contactPref || "").trim(),
      contactAuth: yn(b.contactAuth),
      addresses: (Array.isArray(b.addresses) ? b.addresses : []).map((a) => ({
        id: String(a.id || "").trim() || String(Math.random()).slice(2),
        label: String(a.label || "").trim(),
        town: String(a.town || "").trim(),
        zone: String(a.zone || "").trim(),
        streetAddress: String(a.streetAddress || "").trim(),
        unit: String(a.unit || "").trim(),
        instructions: String(a.instructions || "").trim(),
        gateCode: String(a.gateCode || "").trim(),
      })),
      defaultId: String(b.defaultId || "").trim(),
      consentTerms: yn(b.consentTerms),
      consentPrivacy: yn(b.consentPrivacy),
      consentMarketing: yn(b.consentMarketing),
    };

    if (!newProfile.defaultId && newProfile.addresses.length) {
      newProfile.defaultId = newProfile.addresses[0].id;
    }

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
// HEALTH
// =========================
app.get("/health", (req, res) =>
  res.json({ ok: true, rid: req.id, now: new Date().toISOString(), uptime: process.uptime() })
);

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
app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  let uploadedPath = req.file?.path || "";
  try {
    const b = req.body || {};
    const user = await User.findById(req.user._id).lean();
    const profile = user?.profile || {};

    if (!yn(b.consent_terms) || !yn(b.consent_accuracy) || !yn(b.consent_dropoff)) {
      safeUnlink(uploadedPath);
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    const required = [
      "town","streetAddress","zone","runType","primaryStore","groceryList","dropoffPref","subsPref","contactPref"
    ];
    for (const k of required) {
      if (!String(b[k] || "").trim()) {
        safeUnlink(uploadedPath);
        return res.status(400).json({ ok: false, error: "Missing required field: " + k });
      }
    }

    const runs = await ensureUpcomingRuns();
    const runType = String(b.runType || "");
    const run = runs[runType];
    if (!run) {
      safeUnlink(uploadedPath);
      return res.status(400).json({ ok: false, error: "Invalid runType." });
    }

    const now = nowTz();
    const opensAt = dayjs(run.opensAt).tz(TZ);
    const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    if (!(now.isAfter(opensAt) && now.isBefore(cutoffAt))) {
      safeUnlink(uploadedPath);
      return res.status(403).json({ ok: false, error: "Ordering is closed for this run." });
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
      uploadedPath = "";
    }

    const pricingSnapshot = computeFeeBreakdown({
      zone: b.zone,
      runType: b.runType,
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

    if (!runUpdate) {
      safeUnlink(uploadedPath);
      return res.status(409).json({ ok: false, error: "This run is full." });
    }

    const customerName = String(profile.fullName || user.name || "").trim();
    const customerLastName = extractLastName(customerName);
    const customerEmail = String(user.email || "").trim().toLowerCase();
    const customerPhone = String(profile.phone || "").trim();

    const created = await Order.create({
      orderId,
      customerName,
      customerLastName,
      customerEmail,
      customerPhone,

      runKey: run.runKey,
      runType,

      customer: { fullName: customerName, email: customerEmail, phone: customerPhone },
      address: {
        town: String(b.town || "").trim(),
        streetAddress: String(b.streetAddress || "").trim(),
        zone: String(b.zone || ""),
      },
      stores: { primary: String(b.primaryStore || "").trim(), extra: extraStores },

      preferences: {
        dropoffPref: String(b.dropoffPref || ""),
        subsPref: String(b.subsPref || ""),
        contactPref: String(b.contactPref || ""),
        contactAuth: true,
      },

      list: { groceryListText: String(b.groceryList || "").trim(), attachment },

      consents: { terms: true, accuracy: true, dropoff: true },

      pricingSnapshot,

      payments: {
        fees: { status: "unpaid", paidAt: null, squarePaymentId: "", note: "" },
        groceries: { status: "unpaid", paidAt: null, squarePaymentId: "", note: "" },
      },

      status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" },
      statusHistory: [{ state: "submitted", note: "", at: new Date(), by: "customer" }],
    });

    const cancelUntilLocal = fmtLocal(cutoffAt.toDate());
    const cancelUntilMs = cutoffAt.toDate().getTime();
    const cancelToken = signCancelToken(orderId, cancelUntilMs);

    // 1) Customer confirmation
    try {
      await sendEmail({
        to: created.customerEmail,
        subject: `TGR Order Received: ${created.orderId}`,
        html: orderReceivedCustomerEmail(created, cancelUntilLocal),
        text: `Order received: ${created.orderId}\nCancel until: ${cancelUntilLocal}\nTrack: ${PUBLIC_SITE_URL}/?tab=status`,
        tag: "order_received_customer",
        metadata: { orderId: created.orderId, runKey: created.runKey, runType: created.runType },
      });
    } catch (e) {
      console.error("Customer email send failed:", e);
    }

    // 2) OPS notification (full details + list)
    try {
      await sendEmail({
        to: OPS_EMAIL_TO,
        subject: `NEW ORDER ${created.orderId} — ${created.runType.toUpperCase()} ${created.runKey}`,
        html: orderReceivedOpsEmail(created, b, cancelUntilLocal),
        text:
          `NEW ORDER ${created.orderId}\n` +
          `Run: ${created.runType} ${created.runKey}\n` +
          `Customer: ${created.customerName} ${created.customerPhone}\n` +
          `Address: ${created.address?.streetAddress}, ${created.address?.town} (${created.address?.zone})\n` +
          `Primary store: ${created.stores?.primary}\n` +
          `Extra stops: ${(created.stores?.extra||[]).join(", ")}\n` +
          `Fees total: ${created.pricingSnapshot?.totalFees}\n\n` +
          `LIST:\n${created.list?.groceryListText || ""}`,
        tag: "order_received_ops",
        metadata: { orderId: created.orderId, runKey: created.runKey, runType: created.runType },
      });
    } catch (e) {
      console.error("OPS email send failed:", e);
    }

    res.json({ ok: true, orderId, runKey: run.runKey, cancelToken, cancelUntilLocal });
  } catch (e) {
    safeUnlink(uploadedPath);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// Order tracking + cancel (unchanged)
// =========================
app.get("/api/orders/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const run = await Run.findOne({ runKey: order.runKey }).lean();
    const cutoffAt = run?.cutoffAt ? dayjs(run.cutoffAt).tz(TZ) : null;
    const now = nowTz();

    const isActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    const cancelEligible = !!(isActive && cutoffAt && now.isBefore(cutoffAt));
    const cancelUntilLocal = cutoffAt ? fmtLocal(cutoffAt.toDate()) : "";

    res.json({
      ok: true,
      order: {
        orderId: order.orderId,
        runKey: order.runKey,
        runType: order.runType,
        createdAtLocal: fmtLocal(order.createdAt),

        customerName: order.customerName || order.customer?.fullName || "",
        customerLastName: order.customerLastName || "",
        customerEmail: order.customerEmail || order.customer?.email || "",
        customerPhone: order.customerPhone || order.customer?.phone || "",

        stores: order.stores,
        address: order.address,
        pricingSnapshot: order.pricingSnapshot,
        payments: order.payments,

        status: {
          state: order.status?.state || "submitted",
          note: order.status?.note || "",
          updatedAtLocal: fmtLocal(order.status?.updatedAt || order.updatedAt),
        },
        statusHistory: (order.statusHistory || []).map((h) => ({
          state: h.state,
          note: h.note || "",
          atLocal: fmtLocal(h.at),
          by: h.by || "system",
        })),

        cancelEligible,
        cancelUntilLocal,
      },
    });
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
      return res.status(403).json({
        ok: false,
        error:
          "Cancellation window closed (past cutoff). Per Terms, cancellations after cutoff may still require paying service/delivery fees or a $75 cancellation fee.",
      });
    }

    const cutoffMs = cutoffAt.toDate().getTime();
    if (v.expMs < cutoffMs - 1000) {
      return res.status(403).json({ ok: false, error: "Cancel token is expired or invalid for this run." });
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
// RUNS + EST endpoint
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
// Placeholder pages
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  const email = String(u?.email || "").toLowerCase();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<h1>Member Portal</h1><p>Signed in as <b>${escapeHtml(email)}</b></p>`);
});

app.get("/admin", requireLogin, requireAdmin, async (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<h1>Admin</h1><p>Admin UI is in your other version. Keep your current admin HTML if you already have it.</p>`);
});

// =========================
// Square webhook + Postmark webhook minimal (unchanged from your existing working versions)
// =========================
app.post("/webhooks/square", webhookLimiter, async (req, res) => {
  try {
    const signatureHeader = req.get("x-square-hmacsha256-signature") || "";
    const body = req.rawBody || "";

    if (!SQUARE_WEBHOOK_SIGNATURE_KEY) return res.status(500).send("Square webhook signature key missing.");

    const valid = await WebhooksHelper.verifySignature({
      requestBody: body,
      signatureHeader,
      signatureKey: SQUARE_WEBHOOK_SIGNATURE_KEY,
      notificationUrl: SQUARE_WEBHOOK_NOTIFICATION_URL,
    });
    if (!valid) return res.status(403).send("Invalid signature");

    return res.status(200).send("ok");
  } catch (e) {
    return res.status(500).send("webhook error: " + String(e));
  }
});

function basicAuthOk(req) {
  if (!POSTMARK_WEBHOOK_USERNAME || !POSTMARK_WEBHOOK_PASSWORD) return true;
  const hdr = req.get("authorization") || "";
  if (!hdr.toLowerCase().startsWith("basic ")) return false;
  const b64 = hdr.slice(6).trim();
  let decoded = "";
  try { decoded = Buffer.from(b64, "base64").toString("utf8"); } catch { return false; }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  const user = decoded.slice(0, idx);
  const pass = decoded.slice(idx + 1);
  return user === POSTMARK_WEBHOOK_USERNAME && pass === POSTMARK_WEBHOOK_PASSWORD;
}

app.post("/webhooks/postmark", webhookLimiter, async (req, res) => {
  try {
    if (!basicAuthOk(req)) {
      res.setHeader("WWW-Authenticate", 'Basic realm="Postmark Webhook"');
      return res.status(401).send("Unauthorized");
    }
    return res.status(200).send("ok");
  } catch (e) {
    return res.status(500).send("postmark webhook error: " + String(e));
  }
});

// =========================
// Root + Boot
// =========================
app.get("/", (_req, res) => res.send("TGR backend up"));

async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");

  initEmail();
  console.log("Email configured:", !!POSTMARK_SERVER_TOKEN, "From:", EMAIL_FROM, "OpsTo:", OPS_EMAIL_TO);

  app.listen(PORT, () => console.log("Server running on port", PORT));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

app.use((err, req, res, _next) => {
  console.error("Unhandled error rid=" + req.id, err);
  if (res.headersSent) return;
  res.status(500).json({ ok: false, error: "Internal server error", rid: req.id });
});