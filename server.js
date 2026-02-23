// ======= server.js (FULL FILE — Postmark + useful extras) =======
//
// Extras added:
// - Security headers (helmet)
// - Compression (compression)
// - Rate limiting (express-rate-limit) + stricter on /auth and /webhooks
// - Request logging (morgan) + request id
// - Safer CORS allowlist handling
// - Robust JSON/raw-body handling for Square webhooks
// - Upload temp cleanup (best-effort) after order creation/failure
// - Better error handler (JSON)
// - Real Admin page UI (runs + orders + status + payments + unmatched)
// - /favicon.ico handler (no noisy 404)
// - /api/debug/profile-complete (quickly tells you why completion fails) (admin-only)
//
// Required installs:
//   npm i postmark square helmet compression morgan express-rate-limit
// Optional (recommended):
//   npm i nanoid

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

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

// Try nanoid; fallback to random string if not installed
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

// Google OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

// Admin allowlist
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// CORS
const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:8888",
  "http://localhost:3000",
];

// Square redirect links (customer-facing)
const SQUARE_PAY_LINKS = {
  groceries: process.env.SQUARE_PAY_GROCERIES_LINK || "",
  fees: process.env.SQUARE_PAY_FEES_LINK || "",
};

const SQUARE_MEMBERSHIP_LINKS = {
  standard: process.env.SQUARE_LINK_STANDARD || "",
  route: process.env.SQUARE_LINK_ROUTE || "",
  access: process.env.SQUARE_LINK_ACCESS || "",
  accesspro: process.env.SQUARE_LINK_ACCESSPRO || "",
};

// Square webhook + API token
const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL =
  process.env.SQUARE_WEBHOOK_NOTIFICATION_URL ||
  "https://api.tobermorygroceryrun.ca/webhooks/square";

const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";

// Payment link slugs (square.link/u/<slug>)
const SQUARE_PAY_FEES_SLUG = process.env.SQUARE_PAY_FEES_SLUG || "r92W6XGs";
const SQUARE_PAY_GROCERIES_SLUG = process.env.SQUARE_PAY_GROCERIES_SLUG || "R0hfr7x8";

// Email (Postmark)
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "orders@tobermorygroceryrun.ca";
const EMAIL_REPLY_TO = process.env.EMAIL_REPLY_TO || EMAIL_FROM;
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://tobermorygroceryrun.ca";

// Uploads
const UPLOAD_DIR = process.env.UPLOAD_DIR || "uploads";

// =========================
// UTIL: ids / helpers
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

function isAdminEmail(email) {
  const e = String(email || "").toLowerCase().trim();
  if (!e) return false;
  if (!ADMIN_EMAILS.length) return true;
  return ADMIN_EMAILS.includes(e);
}

function nowTz() {
  return dayjs().tz(TZ);
}

function fmtLocal(d) {
  if (!d) return "";
  return dayjs(d).tz(TZ).format("ddd MMM D, h:mma");
}

// =========================
// UTIL: Square client
// =========================
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

// Request ID + attach early
app.use((req, res, next) => {
  req.id = req.get("x-request-id") || makeReqId();
  res.setHeader("x-request-id", req.id);
  next();
});

// Security headers
app.use(
  helmet({
    // You’re serving HTML from backend for /admin and /member; keep defaults
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// Compression
app.use(compression());

// Logging
app.use(
  morgan(
    ":date[iso] :remote-addr :method :url :status :res[content-length] - :response-time ms rid=:req[x-request-id]",
    { skip: () => NODE_ENV === "test" }
  )
);

// Rate limiting (general)
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 240, // per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Tighter limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
});
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600, // webhooks can burst; keep higher
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS (allowlist)
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
  })
);

// Raw body capture for Square signature validation
app.use(
  express.json({
    limit: "5mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Sessions
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

// Quiet favicon 404 spam
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
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
});

// Best-effort cleanup of temp uploads (don’t let disk fill)
function safeUnlink(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, () => {});
}

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

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const WebhookEvent = mongoose.model("WebhookEvent", WebhookEventSchema);
const UnmatchedPayment = mongoose.model("UnmatchedPayment", UnmatchedPaymentSchema);
const PaymentLinkCache = mongoose.model("PaymentLinkCache", PaymentLinkCacheSchema);

// =========================
// PROFILE COMPLETION LOGIC + DEBUG
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
// RUN CALENDAR
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

function canEmail() {
  return !!(POSTMARK_SERVER_TOKEN && EMAIL_FROM);
}

function initEmail() {
  if (!POSTMARK_SERVER_TOKEN) return;
  postmarkClient = new postmark.ServerClient(POSTMARK_SERVER_TOKEN);
}

async function sendEmail(to, subject, html) {
  if (!canEmail() || !postmarkClient) return { ok: false, skipped: true };

  await postmarkClient.sendEmail({
    From: EMAIL_FROM,
    To: to,
    ReplyTo: EMAIL_REPLY_TO || undefined,
    Subject: subject,
    HtmlBody: html,
    MessageStream: "outbound",
  });

  return { ok: true };
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
// PAYMENT LINK RESOLUTION (slug -> payment_link_id)
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
// WEBHOOK HELPERS
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

app.post("/api/profile", requireLogin, async (req, res) => {
  try {
    const b = req.body || {};
    const u = await User.findById(req.user._id);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    const profile = (u.profile && typeof u.profile === "object") ? u.profile : { version: 1 };

    profile.fullName = String(b.fullName || "").trim();
    profile.preferredName = String(b.preferredName || "").trim();
    profile.phone = String(b.phone || "").trim();
    profile.altPhone = String(b.altPhone || "").trim();
    profile.contactPref = String(b.contactPref || "").trim();

    profile.contactAuth = yn(b.contactAuth);

    profile.subsDefault = String(b.subsDefault || "").trim();
    profile.dropoffDefault = String(b.dropoffDefault || "").trim();
    profile.notes = String(b.notes || "").trim();

    const addresses = Array.isArray(b.addresses) ? b.addresses : [];
    profile.addresses = addresses.map((a) => ({
      id: String(a.id || "").trim() || String(Math.random()).slice(2),
      label: String(a.label || "").trim(),
      town: String(a.town || "").trim(),
      zone: String(a.zone || "").trim(),
      streetAddress: String(a.streetAddress || "").trim(),
      unit: String(a.unit || "").trim(),
      instructions: String(a.instructions || "").trim(),
      gateCode: String(a.gateCode || "").trim(),
    }));

    profile.defaultId = String(b.defaultId || "").trim();
    if (!profile.defaultId && profile.addresses.length) profile.defaultId = profile.addresses[0].id;

    profile.consentTerms = yn(b.consentTerms);
    profile.consentPrivacy = yn(b.consentPrivacy);
    profile.consentMarketing = yn(b.consentMarketing);

    profile.complete = isProfileComplete(profile);
    profile.completedAt = profile.complete
      ? (profile.completedAt || new Date().toISOString())
      : (profile.completedAt || null);

    u.profile = profile;
    await u.save();

    res.json({
      ok: true,
      profileComplete: profile.complete === true,
      profileMissing: profileMissingReasons(profile),
      profile: u.profile,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Admin-only debug endpoint (handy when diagnosing user account issues)
app.get("/api/debug/profile-complete", requireLogin, requireAdmin, async (req, res) => {
  const email = String(req.query.email || "").toLowerCase().trim();
  if (!email) return res.status(400).json({ ok: false, error: "Provide ?email=" });
  const u = await User.findOne({ email }).lean();
  if (!u) return res.status(404).json({ ok: false, error: "User not found" });
  res.json({
    ok: true,
    email,
    profileComplete: isProfileComplete(u.profile || {}),
    missing: profileMissingReasons(u.profile || {}),
    profile: u.profile || {},
  });
});

// =========================
// HEALTH
// =========================
app.get("/health", (_req, res) =>
  res.json({ ok: true, rid: _req.id, now: new Date().toISOString(), uptime: process.uptime() })
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

  const url = SQUARE_PAY_LINKS[kind];
  if (!url) return res.status(500).json({ ok: false, error: "Missing Square pay link for " + kind });

  res.json({ ok: true, kind, checkoutUrl: url });
});

app.get("/pay/groceries", (_req, res) => {
  if (!SQUARE_PAY_LINKS.groceries) return res.status(500).send("Missing SQUARE_PAY_GROCERIES_LINK");
  res.redirect(SQUARE_PAY_LINKS.groceries);
});

app.get("/pay/fees", (_req, res) => {
  if (!SQUARE_PAY_LINKS.fees) return res.status(500).send("Missing SQUARE_PAY_FEES_LINK");
  res.redirect(SQUARE_PAY_LINKS.fees);
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

    const required = ["town","streetAddress","zone","runType","primaryStore","groceryList","dropoffPref","subsPref","contactPref"];
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
      // We keep the file on disk for now; you can later move this to S3/R2.
      // If you want to auto-delete after X days, tell me and I’ll add a cleanup job.
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

    // transactional email: order received
    try {
      if (created?.customer?.email) {
        await sendEmail(created.customer.email, `TGR Order Received: ${created.orderId}`, orderReceivedEmail(created));
      }
    } catch (e) {
      console.error("Email send failed:", String(e));
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
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Per-order payment launch: sets pending, returns Square URL
app.post("/api/orders/:orderId/pay/:kind", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const kind = String(req.params.kind || "").trim().toLowerCase();
    if (!["fees", "groceries"].includes(kind)) return res.status(400).json({ ok: false, error: "Invalid kind" });

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const url = kind === "fees" ? SQUARE_PAY_LINKS.fees : SQUARE_PAY_LINKS.groceries;
    if (!url) return res.status(500).json({ ok: false, error: "Pay link missing for " + kind });

    order.payments[kind].status = "pending";
    order.payments[kind].note = `Customer launched Square payment for ${kind}.`;
    await order.save();

    res.json({ ok: true, orderId, kind, checkoutUrl: url });
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

    try {
      if (order.customer?.email) {
        if (state === "out_for_delivery") {
          await sendEmail(order.customer.email, `TGR Out for delivery: ${order.orderId}`, outForDeliveryEmail(order));
        }
        if (state === "delivered") {
          await sendEmail(order.customer.email, `TGR Delivered: ${order.orderId}`, deliveredEmail(order));
        }
      }
    } catch (e) {
      console.error("Email send failed:", String(e));
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
    if (!["unpaid", "pending", "paid"].includes(status)) return res.status(400).json({ ok: false, error: "Invalid status" });

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

// =========================
// MEMBER + ADMIN PAGES
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  const email = String(u?.email || "").toLowerCase();
  const orders = await Order.find({ "customer.email": email }).sort({ createdAt: -1 }).limit(25).lean();

  const rows = orders
    .map((o) => {
      const status = o.status?.state || "submitted";
      const when = fmtLocal(o.createdAt);
      const primary = o.stores?.primary || "—";
      const town = o.address?.town || "—";
      const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
      const fp = o.payments?.fees?.status || "unpaid";
      const gp = o.payments?.groceries?.status || "unpaid";
      return `<tr>
        <td style="padding:10px 8px;border-top:1px solid #ddd;font-weight:900;">${escapeHtml(o.orderId)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(when)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(primary)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;">${escapeHtml(town)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;font-weight:900;">${escapeHtml(status)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;">$${escapeHtml(fees)}</td>
        <td style="padding:10px 8px;border-top:1px solid #ddd;">Fees: ${escapeHtml(fp)}<br>Groceries: ${escapeHtml(gp)}</td>
      </tr>`;
    })
    .join("");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Member Portal</title></head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:1100px;margin:0 auto;">
<h1 style="margin:0 0 6px;">Member Portal</h1>
<div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(email)}</strong></div>

<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
<a href="${PUBLIC_SITE_URL}/" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Back to site</a>
<a href="/pay/groceries" style="padding:12px 14px;border:1px solid #e3342f;background:#e3342f;color:#fff;border-radius:12px;text-decoration:none;font-weight:900;">Pay Grocery Total</a>
<a href="/pay/fees" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Pay Service & Delivery Fees</a>
<a href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
</div>

<h2 style="margin:0 0 8px;">Recent orders</h2>
<table style="width:100%;border-collapse:collapse;">
<thead><tr>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Order ID</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Created</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Store</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Town</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Status</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Fees</th>
<th style="text-align:left;padding:10px 8px;border-bottom:2px solid #ddd;">Payments</th>
</tr></thead>
<tbody>${rows || `<tr><td colspan="7" style="padding:10px 8px;color:#666;">No orders yet.</td></tr>`}</tbody>
</table>
</body></html>`);
});

// Real Admin UI
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
        const [kind, st] = spec.split(":");
        await setPaid(oid, kind, st);
      });
    });
  }

  async function loadUnmatched(){
    const data = await j("/api/admin/unmatched-payments");
    const items = data.items || [];
    if(!items.length){
      unmatchedBox.textContent = "None 🎉";
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
// SQUARE WEBHOOK (auto-mark paid by payment link)
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

    if (!paymentId) {
      await UnmatchedPayment.create({
        squareEventId: eventId,
        squareEventType: eventType,
        note,
        extractedOrderId: orderId,
        reason: "No paymentId found",
        raw: evt,
      });
      return res.status(200).send("ok");
    }
    if (!orderId) {
      await UnmatchedPayment.create({
        squareEventId: eventId,
        squareEventType: eventType,
        squarePaymentId: paymentId,
        paymentLinkId,
        note,
        reason: "No TGR orderId in note",
        raw: evt,
      });
      return res.status(200).send("ok");
    }
    if (!bucket) {
      await UnmatchedPayment.create({
        squareEventId: eventId,
        squareEventType: eventType,
        squarePaymentId: paymentId,
        paymentLinkId,
        note,
        extractedOrderId: orderId,
        reason: "Could not map paymentLinkId",
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
// ROOT
// =========================
app.get("/", (_req, res) => res.send("TGR backend up"));

// =========================
// BOOT
// =========================
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

// =========================
// FALLBACK ERROR HANDLER
// =========================
app.use((err, req, res, _next) => {
  console.error("Unhandled error rid=" + req.id, err);
  if (res.headersSent) return;
  res.status(500).json({ ok: false, error: "Internal server error", rid: req.id });
});