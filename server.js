// ======= server.js (FULL FILE) — TGR backend =======
// Express + MongoDB + Google OAuth + Account Profile (FIXED persistence for Mixed) + Runs + Estimator + Orders + Admin UI
// Square: pay links + Square webhook (auto-mark fees/groceries paid by Payment Link ID)
// Postmark: sending + Postmark webhooks (Delivered/Open/Click/Bounce/SpamComplaint/SubscriptionChange)
//
// Required installs:
//   npm i express mongoose multer cookie-parser express-session cors connect-mongo passport passport-google-oauth20
//   npm i square postmark helmet compression morgan express-rate-limit
// Optional (recommended):
//   npm i nanoid
//
// Render ENV (minimum):
//   MONGO_URI (or MONGODB_URI)
//   SESSION_SECRET
//   GOOGLE_CLIENT_ID
//   GOOGLE_CLIENT_SECRET
//   GOOGLE_CALLBACK_URL=https://api.tobermorygroceryrun.ca/auth/google/callback
//   PUBLIC_SITE_URL=https://tobermorygroceryrun.ca
//
// Postmark ENV:
//   POSTMARK_SERVER_TOKEN
//   POSTMARK_MESSAGE_STREAM=outbound
//   EMAIL_FROM=orders@tobermorygroceryrun.ca
//   EMAIL_REPLY_TO=orders@tobermorygroceryrun.ca
//   POSTMARK_WEBHOOK_USERNAME=...
//   POSTMARK_WEBHOOK_PASSWORD=...
//
// Square ENV:
//   SQUARE_ACCESS_TOKEN
//   SQUARE_WEBHOOK_SIGNATURE_KEY
//   SQUARE_WEBHOOK_NOTIFICATION_URL=https://api.tobermorygroceryrun.ca/webhooks/square
//   SQUARE_PAY_FEES_SLUG=r92W6XGs
//   SQUARE_PAY_GROCERIES_SLUG=R0hfr7x8
//   SQUARE_PAY_FEES_LINK=https://square.link/u/r92W6XGs
//   SQUARE_PAY_GROCERIES_LINK=https://square.link/u/R0hfr7x8
//   SQUARE_LINK_STANDARD=https://square.link/u/iaziCZjG
//   SQUARE_LINK_ROUTE=https://square.link/u/P5ROgqyp
//   SQUARE_LINK_ACCESS=https://square.link/u/lHtHtvqG
//   SQUARE_LINK_ACCESSPRO=https://square.link/u/S0Y5Fysa
//
// Admin ENV (optional):
//   ADMIN_EMAILS=nickb@tobermorygroceryrun.ca,another@domain.com

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const fs = require("fs");

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
try {
  nanoid = require("nanoid").nanoid;
} catch {
  nanoid = null;
}

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

const POSTMARK_WEBHOOK_USERNAME = process.env.POSTMARK_WEBHOOK_USERNAME || "";
const POSTMARK_WEBHOOK_PASSWORD = process.env.POSTMARK_WEBHOOK_PASSWORD || "";

// Square links and webhook
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

// raw body capture for Square signature verification
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
  try {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  } catch {}
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

    email: {
      lastMessageId: { type: String, default: "" },
      lastEvent: { type: String, default: "" },
      lastEventAt: { type: Date, default: null },
      lastDetails: { type: String, default: "" },
      suppressed: { type: Boolean, default: false },
      suppressReason: { type: String, default: "" },
    },
  },
  { timestamps: true }
);

const WebhookEventSchema = new mongoose.Schema(
  { eventId: { type: String, unique: true, index: true }, type: { type: String, default: "" } },
  { timestamps: true }
);

const UnmatchedPaymentSchema = new mongoose.Schema(
  {
    receivedAt: { type: Date, default: Date.now },
    squareEventId: { type: String, default: "" },
    squareEventType: { type: String, default: "" },
    squarePaymentId: { type: String, default: "" },
    paymentLinkId: { type: String, default: "" },
    note: { type: String, default: "" },
    extractedOrderId: { type: String, default: "" },
    reason: { type: String, default: "" },
    raw: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
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

const EmailEventSchema = new mongoose.Schema(
  {
    provider: { type: String, default: "postmark" },
    recordType: { type: String, default: "" },
    messageId: { type: String, default: "" },
    messageStream: { type: String, default: "" },
    recipient: { type: String, default: "" },
    tag: { type: String, default: "" },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    occurredAt: { type: Date, default: Date.now },
    details: { type: String, default: "" },
    eventKey: { type: String, unique: true, index: true },
    raw: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true }
);

const SuppressedEmailSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, index: true },
    reason: { type: String, default: "" }, // hard-bounce | spam-complaint | manual
    provider: { type: String, default: "postmark" },
    firstAt: { type: Date, default: Date.now },
    lastAt: { type: Date, default: Date.now },
    lastDetails: { type: String, default: "" },
  },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const WebhookEvent = mongoose.model("WebhookEvent", WebhookEventSchema);
const UnmatchedPayment = mongoose.model("UnmatchedPayment", UnmatchedPaymentSchema);
const PaymentLinkCache = mongoose.model("PaymentLinkCache", PaymentLinkCacheSchema);
const EmailEvent = mongoose.model("EmailEvent", EmailEventSchema);
const SuppressedEmail = mongoose.model("SuppressedEmail", SuppressedEmailSchema);

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

function profileMissingReasons(profile) {
  const p = profile || {};
  const reasons = [];
  if (!String(p.fullName || "").trim()) reasons.push("missing fullName");
  if (!String(p.phone || "").trim()) reasons.push("missing phone");
  if (!String(p.contactPref || "").trim()) reasons.push("missing contactPref");
  if (p.contactAuth !== true) reasons.push("contactAuth not true");

  const addresses = Array.isArray(p.addresses) ? p.addresses : [];
  const hasAddress = addresses.some((a) => {
    const street = String(a.streetAddress || "").trim();
    const town = String(a.town || "").trim();
    const zone = String(a.zone || "").trim();
    return !!street && !!town && !!zone;
  });
  if (!hasAddress) reasons.push("missing valid address (street/town/zone)");

  if (p.consentTerms !== true) reasons.push("consentTerms not true");
  if (p.consentPrivacy !== true) reasons.push("consentPrivacy not true");
  return reasons;
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
      !run.lastRecalcAt || dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(2, "minute").toDate());

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

async function isSuppressedEmail(email) {
  const e = String(email || "").toLowerCase().trim();
  if (!e) return false;
  const s = await SuppressedEmail.findOne({ email: e }).lean();
  return !!s;
}

async function sendEmail({ to, subject, html, text, tag, metadata, messageStream }) {
  if (!canEmail()) return { ok: false, skipped: true, reason: "email_not_configured" };

  const recipient = String(to || "").trim().toLowerCase();
  if (!recipient) return { ok: false, skipped: true, reason: "missing_to" };

  if (await isSuppressedEmail(recipient)) {
    return { ok: false, skipped: true, reason: "recipient_suppressed" };
  }

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
    <div style="max-width:720px;margin:0 auto;background:#111;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:18px;color:#fff;">
      <div style="font-size:20px;font-weight:900;margin-bottom:10px;">${escapeHtml(title)}</div>
      <div style="color:rgba(255,255,255,.85);font-size:15px;line-height:1.55;">${bodyHtml}</div>
      <div style="margin-top:14px;color:rgba(255,255,255,.65);font-size:12px;">
        Tobermory Grocery Run • ${escapeHtml(PUBLIC_SITE_URL)}
      </div>
    </div>
  </div>`;
}

function orderReceivedEmail(order) {
  const orderId = escapeHtml(order.orderId);
  const trackUrl = `${PUBLIC_SITE_URL}/?tab=status`;
  const body = `
    <div style="padding:12px;border:1px solid rgba(227,52,47,.35);background:rgba(227,52,47,.12);border-radius:12px;margin:12px 0;">
      <div style="font-weight:900;font-size:16px;">Your Order ID:</div>
      <div style="font-weight:1000;font-size:24px;letter-spacing:.5px;margin-top:4px;">${orderId}</div>
      <div style="margin-top:8px;color:rgba(255,255,255,.9);">
        When paying in Square, paste <strong>${orderId}</strong> into the customer note.
      </div>
    </div>
    <div><strong>Run:</strong> ${escapeHtml(order.runType)} (${escapeHtml(order.runKey)})</div>
    <div style="margin-top:10px;">Track: <a href="${trackUrl}" style="color:#fff;text-decoration:underline;">${escapeHtml(trackUrl)}</a></div>
  `;
  return emailShell("Order received", body);
}

function outForDeliveryEmail(order) {
  const orderId = escapeHtml(order.orderId);
  const trackUrl = `${PUBLIC_SITE_URL}/?tab=status`;
  const body = `
    <div style="font-weight:900;">Order</div>
    <div style="font-size:22px;font-weight:1000;margin:6px 0;">${orderId}</div>
    <div>Your order is <strong>out for delivery</strong>.</div>
    <div style="margin-top:10px;">Track: <a href="${trackUrl}" style="color:#fff;text-decoration:underline;">${escapeHtml(trackUrl)}</a></div>
  `;
  return emailShell("Out for delivery", body);
}

function deliveredEmail(order) {
  const orderId = escapeHtml(order.orderId);
  const body = `
    <div style="font-weight:900;">Order</div>
    <div style="font-size:22px;font-weight:1000;margin:6px 0;">${orderId}</div>
    <div>Your order has been marked <strong>delivered</strong>. Thank you.</div>
  `;
  return emailShell("Delivered", body);
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

  if (found.fees) {
    paymentLinkState.fees.paymentLinkId = String(found.fees.id || "");
    paymentLinkState.fees.url = String(found.fees.url || "");
    await PaymentLinkCache.updateOne(
      { key: "fees" },
      {
        $set: {
          key: "fees",
          slug: paymentLinkState.fees.slug,
          paymentLinkId: paymentLinkState.fees.paymentLinkId,
          paymentLinkUrl: paymentLinkState.fees.url,
          refreshedAt: new Date(),
        },
      },
      { upsert: true }
    );
  }

  if (found.groceries) {
    paymentLinkState.groceries.paymentLinkId = String(found.groceries.id || "");
    paymentLinkState.groceries.url = String(found.groceries.url || "");
    await PaymentLinkCache.updateOne(
      { key: "groceries" },
      {
        $set: {
          key: "groceries",
          slug: paymentLinkState.groceries.slug,
          paymentLinkId: paymentLinkState.groceries.paymentLinkId,
          paymentLinkUrl: paymentLinkState.groceries.url,
          refreshedAt: new Date(),
        },
      },
      { upsert: true }
    );
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
    profileMissing: u?.profile ? profileMissingReasons(u.profile) : [],
    isAdmin: !!u?.email && isAdminEmail(u.email),
  });
});

app.get("/api/profile", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  res.json({
    ok: true,
    profile: u?.profile || {},
    profileComplete: isProfileComplete(u?.profile || {}),
    profileMissing: u?.profile ? profileMissingReasons(u.profile) : [],
    email: u?.email || "",
    name: u?.name || "",
    photo: u?.photo || "",
  });
});

/**
 * IMPORTANT FIX:
 * User.profile is Schema.Types.Mixed, so Mongoose may NOT persist nested mutations reliably.
 * We replace the whole object and markModified("profile") before save.
 */
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

    res.json({
      ok: true,
      profileComplete: newProfile.complete === true,
      profileMissing: profileMissingReasons(newProfile),
      profile: newProfile,
    });
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
// CHECKOUT LINKS
// =========================
app.post("/api/memberships/checkout", (req, res) => {
  const tier = String(req.body?.tier || "").trim().toLowerCase();
  const allowed = new Set(["standard", "route", "access", "accesspro"]);
  if (!allowed.has(tier)) return res.status(400).json({ ok: false, error: "Invalid tier" });

  const url = SQUARE_MEMBERSHIP_LINKS[tier];
  if (!url) return res.status(500).json({ ok: false, error: "Missing Square membership link for " + tier });

  res.json({ ok: true, tier, checkoutUrl: url });
});

app.post("/api/payments/checkout", (req, res) => {
  const kind = String(req.body?.kind || "").trim().toLowerCase();
  const allowed = new Set(["groceries", "fees"]);
  if (!allowed.has(kind)) return res.status(400).json({ ok: false, error: "Invalid payment kind" });

  const url = kind === "fees" ? SQUARE_PAY_LINKS.fees : SQUARE_PAY_LINKS.groceries;
  if (!url) return res.status(500).json({ ok: false, error: "Missing Square pay link for " + kind });

  res.json({ ok: true, kind, checkoutUrl: url });
});

app.get("/pay/groceries", (_req, res) => res.redirect(SQUARE_PAY_LINKS.groceries));
app.get("/pay/fees", (_req, res) => res.redirect(SQUARE_PAY_LINKS.fees));

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
      "town",
      "streetAddress",
      "zone",
      "runType",
      "primaryStore",
      "groceryList",
      "dropoffPref",
      "subsPref",
      "contactPref",
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
      uploadedPath = ""; // keep file for now
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

    const created = await Order.create({
      orderId,
      runKey: run.runKey,
      runType,
      customer: {
        fullName: String(profile.fullName || user.name || "").trim(),
        email: String(user.email || "").trim().toLowerCase(),
        phone: String(profile.phone || "").trim(),
      },
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

    // Postmark email with Tag + Metadata for webhook linking
    try {
      const pm = await sendEmail({
        to: created.customer.email,
        subject: `TGR Order Received: ${created.orderId}`,
        html: orderReceivedEmail(created),
        text: `Order received: ${created.orderId}\nTrack: ${PUBLIC_SITE_URL}/?tab=status`,
        tag: "order_received",
        metadata: { orderId: created.orderId, runKey: created.runKey, runType: created.runType },
      });
      if (pm?.ok && pm.messageId) {
        await Order.updateOne(
          { _id: created._id },
          { $set: { "email.lastMessageId": pm.messageId, "email.lastEvent": "sent", "email.lastEventAt": new Date() } }
        );
      }
    } catch (e) {
      console.error("Postmark send failed:", String(e));
    }

    res.json({ ok: true, orderId, runKey: run.runKey });
  } catch (e) {
    safeUnlink(uploadedPath);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Public tracking by orderId
app.get("/api/orders/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    res.json({
      ok: true,
      order: {
        orderId: order.orderId,
        runKey: order.runKey,
        runType: order.runType,
        createdAtLocal: fmtLocal(order.createdAt),
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
        email: order.email || {},
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// ADMIN API
// =========================
app.get("/api/admin/runs", requireLogin, requireAdmin, async (_req, res) => {
  const runs = await ensureUpcomingRuns();
  res.json({ ok: true, runs });
});

app.get("/api/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  const runKey = String(req.query.runKey || "").trim();
  const status = String(req.query.status || "").trim();
  const q = {};
  if (runKey) q.runKey = runKey;
  if (status) q["status.state"] = status;

  const orders = await Order.find(q).sort({ createdAt: -1 }).limit(500).lean();
  res.json({ ok: true, orders });
});

app.patch("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const state = String(req.body?.state || "").trim();
    const note = String(req.body?.note || "").trim();
    if (!AllowedStates.includes(state)) return res.status(400).json({ ok: false, error: "Invalid state" });

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const by = String(req.user?.email || "admin").toLowerCase();

    order.status.state = state;
    order.status.note = note;
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state, note, at: new Date(), by });

    await order.save();

    // Send status emails for high-value states
    try {
      if (order.customer?.email) {
        if (state === "out_for_delivery") {
          const pm = await sendEmail({
            to: order.customer.email,
            subject: `TGR Out for delivery: ${order.orderId}`,
            html: outForDeliveryEmail(order),
            text: `Out for delivery: ${order.orderId}\nTrack: ${PUBLIC_SITE_URL}/?tab=status`,
            tag: "out_for_delivery",
            metadata: { orderId: order.orderId, runKey: order.runKey, runType: order.runType },
          });
          if (pm?.ok && pm.messageId) {
            order.email.lastMessageId = pm.messageId;
            order.email.lastEvent = "sent_out_for_delivery";
            order.email.lastEventAt = new Date();
            await order.save();
          }
        }
        if (state === "delivered") {
          const pm = await sendEmail({
            to: order.customer.email,
            subject: `TGR Delivered: ${order.orderId}`,
            html: deliveredEmail(order),
            text: `Delivered: ${order.orderId}`,
            tag: "delivered",
            metadata: { orderId: order.orderId, runKey: order.runKey, runType: order.runType },
          });
          if (pm?.ok && pm.messageId) {
            order.email.lastMessageId = pm.messageId;
            order.email.lastEvent = "sent_delivered";
            order.email.lastEventAt = new Date();
            await order.save();
          }
        }
      }
    } catch (e) {
      console.error("Postmark send failed:", String(e));
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.patch("/api/admin/orders/:orderId/payment", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const kind = String(req.body?.kind || "").trim().toLowerCase();
    const status = String(req.body?.status || "").trim().toLowerCase();
    if (!["fees", "groceries"].includes(kind)) return res.status(400).json({ ok: false, error: "Invalid kind" });
    if (!["unpaid", "pending", "paid"].includes(status))
      return res.status(400).json({ ok: false, error: "Invalid status" });

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.payments[kind].status = status;
    order.payments[kind].paidAt = status === "paid" ? new Date() : null;
    order.payments[kind].note = String(req.body?.note || "").trim();

    await order.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/admin/unmatched-payments", requireLogin, requireAdmin, async (_req, res) => {
  const items = await UnmatchedPayment.find({}).sort({ createdAt: -1 }).limit(200).lean();
  res.json({ ok: true, items });
});

app.get("/api/admin/email-events", requireLogin, requireAdmin, async (req, res) => {
  const orderId = String(req.query.orderId || "").trim().toUpperCase();
  const recipient = String(req.query.recipient || "").trim().toLowerCase();
  const q = {};
  if (orderId) q["metadata.orderId"] = orderId;
  if (recipient) q.recipient = recipient;
  const items = await EmailEvent.find(q).sort({ occurredAt: -1 }).limit(500).lean();
  res.json({ ok: true, items });
});

app.get("/api/admin/suppressions", requireLogin, requireAdmin, async (_req, res) => {
  const items = await SuppressedEmail.find({}).sort({ lastAt: -1 }).limit(500).lean();
  res.json({ ok: true, items });
});

// =========================
// MEMBER PAGE
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  const email = String(u?.email || "").toLowerCase();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Member Portal</title></head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:900px;margin:0 auto;">
<h1 style="margin:0 0 8px;">Member Portal</h1>
<div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(email)}</strong></div>
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
  <a href="${PUBLIC_SITE_URL}/" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Back to site</a>
  <a href="/pay/groceries" style="padding:12px 14px;border:1px solid #e3342f;background:#e3342f;color:#fff;border-radius:12px;text-decoration:none;font-weight:900;">Pay Grocery Total</a>
  <a href="/pay/fees" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Pay Service & Delivery Fees</a>
  <a href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
</div>
<div style="color:#444;">Tracking is on the public site under “Live Status” using your Order ID.</div>
</body></html>`);
});

// =========================
// ADMIN UI (REAL DASHBOARD)
// =========================
app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TGR Admin</title>
</head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:1200px;margin:0 auto;">
  <h1 style="margin:0 0 8px;">Admin</h1>
  <div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(String(req.user.email||""))}</strong></div>

  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
    <a href="${PUBLIC_SITE_URL}/" style="padding:10px 12px;border:1px solid #ddd;border-radius:10px;text-decoration:none;color:#111;font-weight:800;">Back to site</a>
    <a href="/api/admin/email-events" style="padding:10px 12px;border:1px solid #ddd;border-radius:10px;text-decoration:none;color:#111;font-weight:800;">Email events</a>
    <a href="/api/admin/suppressions" style="padding:10px 12px;border:1px solid #ddd;border-radius:10px;text-decoration:none;color:#111;font-weight:800;">Suppressions</a>
    <a href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}" style="padding:10px 12px;border:1px solid #ddd;border-radius:10px;text-decoration:none;color:#111;font-weight:800;">Log out</a>
  </div>

  <div style="border:1px solid #ddd;border-radius:12px;padding:12px;">
    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">
      <div>
        <label style="font-weight:800;">Run</label><br>
        <select id="runKeySel" style="padding:10px;border-radius:10px;border:1px solid #ddd;min-width:280px;"></select>
      </div>
      <div>
        <label style="font-weight:800;">Status filter</label><br>
        <select id="statusSel" style="padding:10px;border-radius:10px;border:1px solid #ddd;min-width:220px;">
          <option value="">All</option>
          ${AllowedStates.map(s=>`<option value="${s}">${s}</option>`).join("")}
        </select>
      </div>
      <button id="refreshBtn" style="padding:10px 12px;border-radius:10px;border:1px solid #111;background:#111;color:#fff;font-weight:900;cursor:pointer;">Refresh</button>
    </div>
  </div>

  <h2 style="margin:16px 0 8px;">Orders</h2>
  <div id="ordersMeta" style="color:#444;margin-bottom:8px;">Loading…</div>
  <div style="overflow:auto;border:1px solid #ddd;border-radius:12px;">
    <table style="width:100%;border-collapse:collapse;min-width:1100px;">
      <thead>
        <tr style="background:#f7f7f7;">
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Order</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Run</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Town/Zone</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Store</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Fees</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Payments</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Status</th>
          <th style="text-align:left;padding:10px;border-bottom:1px solid #ddd;">Actions</th>
        </tr>
      </thead>
      <tbody id="ordersBody"></tbody>
    </table>
  </div>

  <h2 style="margin:18px 0 8px;">Unmatched payments</h2>
  <div id="unmatchedBox" style="border:1px solid #ddd;border-radius:12px;padding:12px;">Loading…</div>

<script>
  async function j(url, opts){
    const r = await fetch(url, Object.assign({ credentials:"include" }, opts||{}));
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok === false) throw new Error(d.error || ("HTTP "+r.status));
    return d;
  }

  const runKeySel = document.getElementById("runKeySel");
  const statusSel = document.getElementById("statusSel");
  const ordersBody = document.getElementById("ordersBody");
  const ordersMeta = document.getElementById("ordersMeta");
  const unmatchedBox = document.getElementById("unmatchedBox");

  function esc(s){
    return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
  }
  function money(n){
    const x = Math.round((Number(n||0)+Number.EPSILON)*100)/100;
    return "$"+x.toFixed(2);
  }

  async function loadRuns(){
    const data = await j("/api/admin/runs");
    const runs = data.runs || {};
    const options = [];
    for(const k of ["local","owen"]){
      const r = runs[k];
      if(!r) continue;
      options.push({ label: r.runKey + " ("+r.type+")", value: r.runKey });
    }
    runKeySel.innerHTML = options.map(o => "<option value='"+esc(o.value)+"'>"+esc(o.label)+"</option>").join("");
  }

  async function setStatus(orderId, state){
    const note = prompt("Optional note for status change:", "");
    await j("/api/admin/orders/"+encodeURIComponent(orderId)+"/status", {
      method:"PATCH",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ state, note: note || "" })
    });
    await refreshAll();
  }

  async function setPaid(orderId, kind, status){
    const note = prompt("Optional note:", "");
    await j("/api/admin/orders/"+encodeURIComponent(orderId)+"/payment", {
      method:"PATCH",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ kind, status, note: note || "" })
    });
    await refreshAll();
  }

  function actionBtns(order){
    const id = order.orderId;

    const statusButtons = ["confirmed","shopping","packed","out_for_delivery","delivered","issue","cancelled"]
      .map(st => "<button data-st='"+st+"' style='padding:8px 10px;border-radius:10px;border:1px solid #ddd;background:#fff;font-weight:900;cursor:pointer;'>"+st+"</button>")
      .join(" ");

    const payButtons =
      "<div style='margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;'>" +
      "<button data-pay='fees:paid' style='padding:8px 10px;border-radius:10px;border:1px solid #ddd;background:#fff;font-weight:900;cursor:pointer;'>Fees paid</button>" +
      "<button data-pay='fees:unpaid' style='padding:8px 10px;border-radius:10px;border:1px solid #ddd;background:#fff;font-weight:900;cursor:pointer;'>Fees unpaid</button>" +
      "<button data-pay='groceries:paid' style='padding:8px 10px;border-radius:10px;border:1px solid #ddd;background:#fff;font-weight:900;cursor:pointer;'>Groceries paid</button>" +
      "<button data-pay='groceries:unpaid' style='padding:8px 10px;border-radius:10px;border:1px solid #ddd;background:#fff;font-weight:900;cursor:pointer;'>Groceries unpaid</button>" +
      "</div>";

    return "<div data-oid='"+esc(id)+"'>" +
      "<div style='display:flex;gap:8px;flex-wrap:wrap;'>" + statusButtons + "</div>" +
      payButtons +
      "</div>";
  }

  function row(order){
    const id = esc(order.orderId);
    const runKey = esc(order.runKey || "—");
    const town = esc(order.address?.town || "—");
    const zone = esc(order.address?.zone || "—");
    const store = esc(order.stores?.primary || "—");
    const fees = money(order.pricingSnapshot?.totalFees || 0);

    const feesPay = esc(order.payments?.fees?.status || "unpaid");
    const grocPay = esc(order.payments?.groceries?.status || "unpaid");

    const st = esc(order.status?.state || "submitted");

    return "<tr>" +
      "<td style='padding:10px;border-top:1px solid #eee;font-weight:1000;white-space:nowrap;'>" + id + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;white-space:nowrap;'>" + runKey + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;'>" + town + " / " + zone + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;'>" + store + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;font-weight:900;'>" + fees + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;'><div><strong>Fees:</strong> "+feesPay+"</div><div><strong>Groceries:</strong> "+grocPay+"</div></td>" +
      "<td style='padding:10px;border-top:1px solid #eee;font-weight:900;white-space:nowrap;'>" + st + "</td>" +
      "<td style='padding:10px;border-top:1px solid #eee;'>" + actionBtns(order) + "</td>" +
    "</tr>";
  }

  async function loadOrders(){
    const runKey = runKeySel.value;
    const status = statusSel.value;
    const qs = new URLSearchParams();
    if(runKey) qs.set("runKey", runKey);
    if(status) qs.set("status", status);

    const data = await j("/api/admin/orders?"+qs.toString());
    const orders = data.orders || [];
    ordersMeta.textContent = orders.length + " orders";
    ordersBody.innerHTML = orders.map(row).join("");

    ordersBody.querySelectorAll("button[data-st]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const wrap = btn.closest("[data-oid]");
        const oid = wrap.getAttribute("data-oid");
        const st = btn.getAttribute("data-st");
        await setStatus(oid, st);
      });
    });

    ordersBody.querySelectorAll("button[data-pay]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const wrap = btn.closest("[data-oid]");
        const oid = wrap.getAttribute("data-oid");
        const spec = btn.getAttribute("data-pay");
        const parts = spec.split(":");
        await setPaid(oid, parts[0], parts[1]);
      });
    });
  }

  async function loadUnmatched(){
    const data = await j("/api/admin/unmatched-payments");
    const items = data.items || [];
    if(!items.length){
      unmatchedBox.textContent = "None";
      return;
    }
    unmatchedBox.innerHTML = items.slice(0,50).map(x => {
      return "<div style='padding:10px;border-top:1px solid #eee;'>" +
        "<div style='font-weight:900;'>"+esc(x.squarePaymentId || "payment")+"</div>" +
        "<div style='color:#444;'>"+esc(x.squareEventType || "")+" • "+esc(x.reason || "")+"</div>" +
        "<div style='color:#444;'>note: "+esc(x.note || "")+"</div>" +
        "</div>";
    }).join("");
  }

  async function refreshAll(){
    await loadOrders();
    await loadUnmatched();
  }

  document.getElementById("refreshBtn").addEventListener("click", refreshAll);
  runKeySel.addEventListener("change", loadOrders);
  statusSel.addEventListener("change", loadOrders);

  (async function boot(){
    await loadRuns();
    await refreshAll();
  })();
</script>
</body>
</html>`);
});

// =========================
// SQUARE WEBHOOK (auto mark paid)
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

    const evt = req.body || {};
    const eventId = String(evt.event_id || "");
    const eventType = String(evt.type || "");

    if (eventId) {
      const exists = await WebhookEvent.findOne({ eventId }).lean();
      if (exists) return res.status(200).send("ok");
      await WebhookEvent.create({ eventId, type: eventType });
    }

    const paymentId = tryExtractPaymentId(evt);
    let note = tryExtractNote(evt);
    let paymentLinkId = tryExtractPaymentLinkId(evt);

    if ((!note || !paymentLinkId) && paymentId) {
      const paymentObj = await retrievePayment(paymentId);
      if (!note) note = String(paymentObj?.note || "");
      if (!paymentLinkId) paymentLinkId = String(paymentObj?.payment_link_id || paymentObj?.source_id || "");
    }

    const orderId = extractOrderIdFromNote(note);

    if (!paymentLinkState.fees.paymentLinkId || !paymentLinkState.groceries.paymentLinkId) {
      await refreshPaymentLinkIds().catch(() => {});
    }

    const bucket = pickBucketByPaymentLinkId(paymentLinkId);

    if (!paymentId || !orderId || !bucket) {
      await UnmatchedPayment.create({
        squareEventId: eventId,
        squareEventType: eventType,
        squarePaymentId: paymentId || "",
        paymentLinkId: paymentLinkId || "",
        note: note || "",
        extractedOrderId: orderId || "",
        reason: !paymentId ? "No paymentId" : !orderId ? "No TGR orderId in note" : "Could not map paymentLinkId",
        raw: evt,
      });
      return res.status(200).send("ok");
    }

    const order = await Order.findOne({ orderId });
    if (!order) {
      await UnmatchedPayment.create({
        squareEventId: eventId,
        squareEventType: eventType,
        squarePaymentId: paymentId,
        paymentLinkId,
        note,
        extractedOrderId: orderId,
        reason: "Order not found",
        raw: evt,
      });
      return res.status(200).send("ok");
    }

    order.payments[bucket].status = "paid";
    order.payments[bucket].paidAt = new Date();
    order.payments[bucket].squarePaymentId = paymentId;
    order.payments[bucket].note = note;

    order.statusHistory.push({
      state: order.status?.state || "submitted",
      note: `${bucket} payment marked PAID via Square webhook (payment ${paymentId})`,
      at: new Date(),
      by: "square-webhook",
    });

    await order.save();
    return res.status(200).send("ok");
  } catch (e) {
    return res.status(500).send("webhook error: " + String(e));
  }
});

// =========================
// POSTMARK WEBHOOK (ALL EVENTS)
// =========================
function basicAuthOk(req) {
  if (!POSTMARK_WEBHOOK_USERNAME || !POSTMARK_WEBHOOK_PASSWORD) return true;
  const hdr = req.get("authorization") || "";
  if (!hdr.toLowerCase().startsWith("basic ")) return false;
  const b64 = hdr.slice(6).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return false;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  const user = decoded.slice(0, idx);
  const pass = decoded.slice(idx + 1);
  return user === POSTMARK_WEBHOOK_USERNAME && pass === POSTMARK_WEBHOOK_PASSWORD;
}

function makeEventKey({ recordType, messageId, recipient, occurredAt, tag }) {
  const base = [
    String(recordType || "").toLowerCase(),
    String(messageId || "").toLowerCase(),
    String(recipient || "").toLowerCase(),
    String(tag || "").toLowerCase(),
    occurredAt ? new Date(occurredAt).toISOString() : "",
  ].join("|");
  let h = 0;
  for (let i = 0; i < base.length; i++) h = (h * 31 + base.charCodeAt(i)) >>> 0;
  return "pm_" + h.toString(16);
}

async function upsertSuppression(email, reason, details) {
  const e = String(email || "").toLowerCase().trim();
  if (!e) return;
  await SuppressedEmail.updateOne(
    { email: e },
    {
      $set: { email: e, provider: "postmark", reason, lastAt: new Date(), lastDetails: String(details || "") },
      $setOnInsert: { firstAt: new Date() },
    },
    { upsert: true }
  );
}

app.post("/webhooks/postmark", webhookLimiter, async (req, res) => {
  try {
    if (!basicAuthOk(req)) {
      res.setHeader("WWW-Authenticate", 'Basic realm="Postmark Webhook"');
      return res.status(401).send("Unauthorized");
    }

    const payload = req.body || {};
    const recordType = String(payload.RecordType || payload.record_type || "").trim();

    const messageId = String(payload.MessageID || payload.MessageId || payload.message_id || "").trim();
    const messageStream = String(payload.MessageStream || payload.MessageStreamID || payload.MessageStreamId || "").trim();

    const recipient = String(payload.Recipient || payload.Email || payload.email || "")
      .trim()
      .toLowerCase();

    const tag = String(payload.Tag || "").trim();
    const metadata = payload.Metadata || payload.metadata || {};

    const occurredAt =
      payload.DeliveredAt ||
      payload.ReceivedAt ||
      payload.BouncedAt ||
      payload.ChangedAt ||
      payload.FirstOpen ||
      payload.OriginalTimestamp ||
      payload.ClickedAt ||
      new Date().toISOString();

    let details = "";
    const rt = recordType.toLowerCase();
    if (rt === "delivered") details = String(payload.Details || payload.details || "");
    if (rt === "bounce") details = String(payload.Description || payload.Details || payload.details || "");
    if (rt === "spamcomplaint") details = String(payload.Description || payload.details || "");
    if (rt === "click") details = String(payload.OriginalLink || payload.Link || payload.Url || "");
    if (rt === "subscriptionchange") details = String(payload.SuppressionReason || payload.ChangeType || payload.Description || "");

    const eventKey = makeEventKey({ recordType, messageId, recipient, occurredAt, tag });

    try {
      await EmailEvent.create({
        provider: "postmark",
        recordType,
        messageId,
        messageStream,
        recipient,
        tag,
        metadata,
        occurredAt: new Date(occurredAt),
        details,
        eventKey,
        raw: payload,
      });
    } catch (e) {
      if (String(e?.code) === "11000") return res.status(200).send("ok"); // duplicate
      throw e;
    }

    const orderIdFromMeta = metadata?.orderId ? String(metadata.orderId).trim().toUpperCase() : "";
    if (orderIdFromMeta) {
      await Order.updateOne(
        { orderId: orderIdFromMeta },
        {
          $set: {
            "email.lastMessageId": messageId || "",
            "email.lastEvent": recordType || "",
            "email.lastEventAt": new Date(occurredAt),
            "email.lastDetails": details || "",
          },
        }
      );
    }

    // Suppression rules:
    // - SpamComplaint: always suppress
    // - Bounce: suppress if hard/permanent
    if (rt === "spamcomplaint") {
      if (recipient) await upsertSuppression(recipient, "spam-complaint", details);
      if (orderIdFromMeta) {
        await Order.updateOne(
          { orderId: orderIdFromMeta },
          { $set: { "email.suppressed": true, "email.suppressReason": "spam-complaint" } }
        );
      }
    }

    if (rt === "bounce") {
      const bounceType = String(payload.Type || payload.BounceType || "").toLowerCase();
      const isHard =
        bounceType.includes("hard") ||
        bounceType.includes("permanent") ||
        String(payload.Description || "").toLowerCase().includes("hard");

      if (isHard && recipient) {
        await upsertSuppression(recipient, "hard-bounce", details);
        if (orderIdFromMeta) {
          await Order.updateOne(
            { orderId: orderIdFromMeta },
            { $set: { "email.suppressed": true, "email.suppressReason": "hard-bounce" } }
          );
        }
      }
    }

    return res.status(200).send("ok");
  } catch (e) {
    return res.status(500).send("postmark webhook error: " + String(e));
  }
});

// =========================
// ROOT + BOOT
// =========================
app.get("/", (_req, res) => res.send("TGR backend up"));

async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");

  initEmail();

  await loadPaymentLinkIdsFromDb().catch(() => {});
  await refreshPaymentLinkIds().catch(() => {});
  setInterval(() => refreshPaymentLinkIds().catch(() => {}), 1000 * 60 * 30);

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