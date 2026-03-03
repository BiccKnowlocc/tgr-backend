// ======= server.js (FULL FILE) — TGR backend =======
// Implements: Google OAuth, required profile onboarding, runs (biweekly), estimator, orders, cancel tokens
// + FULL admin UI and admin endpoints (search/status/cancel/delete/export)
// + MEMBER PORTAL (/member) + order list + cancel button (before cutoff) + LIVE MAP (active orders only)
//
// AddressComplete reliability:
// - Proxies AddressComplete JS/CSS through this backend.
//   GET /vendor/addresscomplete.js
//   GET /vendor/addresscomplete.css
//   GET /api/public/addresscomplete
//
// ADDED (ONLY what’s necessary for auto membership activation):
// - Square webhook endpoint: POST /webhooks/square
// - Signature verification using raw body
// - Membership activation by buyer_email_address + amount_money.amount (cents)
// - Updates User: membershipLevel, membershipStatus, renewalDate
//
// RESTORED / ADDED (member tools):
// - GET /member  (member portal HTML)
// - GET /api/member/orders
// - POST /api/member/cancel-membership
// - GET /api/member/tracking-token?orderId=...

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

// Postmark outbound
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || "";
const POSTMARK_FROM_EMAIL =
  process.env.POSTMARK_FROM_EMAIL || "orders@tobermorygroceryrun.ca";
const POSTMARK_MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || "outbound";

const pmClient = POSTMARK_SERVER_TOKEN
  ? new postmark.ServerClient(POSTMARK_SERVER_TOKEN)
  : null;

// Postmark webhooks (your existing Render env var names)
const POSTMARK_WEBHOOK_USERNAME = process.env.postmark_webhook_username || "";
const POSTMARK_WEBHOOK_PASSWORD = process.env.postmark_webhook_password || "";

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
// Square webhook config (membership auto-activation)
// =========================
const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL = process.env.SQUARE_WEBHOOK_NOTIFICATION_URL || "";

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

// IMPORTANT: keep rawBody for Square signature verification
app.use(
  express.json({
    limit: "6mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
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

// ===== Postmark outbound helper =====
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

function memberPortalUrl() {
  return "https://api.tobermorygroceryrun.ca/member";
}

function nextDow(targetDow, from) {
  let d = dayjs(from).tz(TZ);
  const current = d.day();
  let diff = (targetDow - current + 7) % 7;
  if (diff === 0) diff = 7;
  return d.add(diff, "day");
}

// ===== Basic-auth helper (for Postmark webhooks) =====
function requireBasicAuth(user, pass) {
  return function (req, res, next) {
    try {
      const hdr = String(req.headers.authorization || "");
      if (!hdr.startsWith("Basic ")) return res.status(401).send("Auth required");

      const decoded = Buffer.from(hdr.slice(6), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      const u = idx >= 0 ? decoded.slice(0, idx) : "";
      const p = idx >= 0 ? decoded.slice(idx + 1) : "";

      const a = Buffer.from(u);
      const b = Buffer.from(String(user));
      const c = Buffer.from(p);
      const d = Buffer.from(String(pass));

      if (a.length !== b.length || c.length !== d.length) return res.status(403).send("Forbidden");
      if (!crypto.timingSafeEqual(a, b) || !crypto.timingSafeEqual(c, d)) return res.status(403).send("Forbidden");

      next();
    } catch {
      res.status(403).send("Forbidden");
    }
  };
}

// =========================
// Square webhook → membership activation helpers
// =========================
const MEMBERSHIP_PRICE_MAP_CENTS = new Map([
  [1500, "standard"],
  [2500, "route"],
  [1200, "access"],
  [2000, "accesspro"],
]);

function addOneMonthISO(fromDate = new Date()) {
  const d = new Date(fromDate.getTime());
  const m = d.getMonth();
  d.setMonth(m + 1);
  if (d.getMonth() !== ((m + 1) % 12)) {
    d.setDate(0);
  }
  return d.toISOString();
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Square signature validation: HMAC-SHA256(sigKey, notificationUrl + rawBody) base64
function verifySquareWebhook(req) {
  try {
    if (!SQUARE_WEBHOOK_SIGNATURE_KEY || !SQUARE_WEBHOOK_NOTIFICATION_URL) return false;

    const headerSig = String(req.headers["x-square-hmacsha256-signature"] || "").trim();
    if (!headerSig) return false;

    const raw = req.rawBody ? req.rawBody.toString("utf8") : "";
    const payload = SQUARE_WEBHOOK_NOTIFICATION_URL + raw;

    const hmac = crypto
      .createHmac("sha256", SQUARE_WEBHOOK_SIGNATURE_KEY)
      .update(payload, "utf8")
      .digest("base64");

    return timingSafeEqualStr(hmac, headerSig);
  } catch {
    return false;
  }
}

async function handleMembershipPaymentEvent(evt) {
  const payment =
    evt?.data?.object?.payment ||
    evt?.data?.object ||
    null;

  if (!payment) return { ok: true, reason: "no_payment" };

  const status = String(payment.status || "").toUpperCase();
  if (status !== "COMPLETED") return { ok: true, reason: "not_completed" };

  const buyerEmail =
    String(payment.buyer_email_address || payment.buyerEmailAddress || "").trim().toLowerCase();
  if (!buyerEmail) return { ok: true, reason: "no_buyer_email" };

  const amountCents = Number(payment.amount_money?.amount ?? payment.amountMoney?.amount ?? NaN);
  if (!Number.isFinite(amountCents)) return { ok: true, reason: "no_amount" };

  const tier = MEMBERSHIP_PRICE_MAP_CENTS.get(amountCents);
  if (!tier) return { ok: true, reason: "amount_not_membership" };

  const u = await User.findOne({ email: buyerEmail });
  if (!u) return { ok: true, reason: "user_not_found" };

  u.membershipLevel = tier;
  u.membershipStatus = "active";
  u.renewalDate = addOneMonthISO(new Date());
  await u.save();

  pmSend(
    buyerEmail,
    `TGR Membership Activated: ${tier.toUpperCase()}`,
    `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
      <h2 style="margin:0 0 10px;">Membership activated ✅</h2>
      <p style="margin:0 0 10px;">Your <strong>${escapeHtml(tier)}</strong> membership is now active.</p>
      <p style="margin:0 0 10px;"><strong>Renewal date:</strong> ${escapeHtml(String(u.renewalDate || ""))}</p>
      <p style="margin:0;">Member Portal: <a href="${escapeHtml(memberPortalUrl())}">${escapeHtml(memberPortalUrl())}</a></p>
    </div>`,
    `Membership activated: ${tier}\nRenewal: ${u.renewalDate}\nPortal: ${memberPortalUrl()}`
  );

  return { ok: true, reason: "activated", tier };
}

// =========================
// Run scheduling (biweekly, DB-driven)
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
  const cutoff = delivery
    .subtract(2, "day")
    .hour(18)
    .minute(0)
    .second(0)
    .millisecond(0); // Fri 6pm
  const opens = delivery
    .subtract(6, "day")
    .hour(0)
    .minute(0)
    .second(0)
    .millisecond(0); // Mon 12am
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

async function getOrCreateNextRun(type) {
  const now = nowTz();

  // Prefer an existing run that has NOT passed cutoff yet
  let existing = await Run.findOne({ type, cutoffAt: { $gt: now.toDate() } })
    .sort({ opensAt: 1 })
    .lean();

  // If found but opensAt is still in the future, force it open now (avoid dead windows)
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

  // No upcoming run in DB: create one.
  const latest = await Run.findOne({ type }).sort({ opensAt: -1 }).lean();

  let delivery;
  if (latest?.runKey) {
    const lastDelivery = runKeyToDayjs(latest.runKey);
    delivery = (lastDelivery || now).add(14, "day");
  } else {
    delivery = type === "local" ? nextDow(6, now) : nextDow(0, now);
  }

  let { cutoff, opens } = computeTimesForDelivery(delivery, type);

  // KEY FIX: if computed opens is still in the future, open immediately.
  if (opens.isAfter(now)) {
    opens = now.subtract(1, "minute");
  }

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

// =========================
// Postmark webhook endpoint (secured)
// =========================
app.post(
  "/webhooks/postmark",
  requireBasicAuth(POSTMARK_WEBHOOK_USERNAME, POSTMARK_WEBHOOK_PASSWORD),
  async (req, res) => {
    try {
      const rt = String(req.body?.RecordType || "");
      const mid = String(req.body?.MessageID || "");
      console.log("Postmark webhook:", rt || "event", mid ? ("MessageID=" + mid) : "");
    } catch {}
    res.json({ ok: true });
  }
);

// =========================
// Square webhook endpoint (membership auto-activation)
// =========================
app.post("/webhooks/square", async (req, res) => {
  if (!verifySquareWebhook(req)) {
    return res.status(403).send("Invalid signature");
  }

  const evt = req.body || {};
  const type = String(evt.type || evt.event_type || "").toLowerCase();

  try {
    if (type === "payment.updated" || type === "payment.created") {
      await handleMembershipPaymentEvent(evt);
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error("Square webhook error:", String(e));
    return res.status(500).json({ ok: false });
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

    // optional: basic order confirmation email
    pmSend(
      String(user.email || "").trim().toLowerCase(),
      `TGR Order Submitted: ${orderId}`,
      `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45;">
        <h2 style="margin:0 0 10px;">Order submitted ✅</h2>
        <p style="margin:0 0 10px;">Your order ID is <strong>${escapeHtml(orderId)}</strong>.</p>
        <p style="margin:0 0 10px;">You can view status in your Member Portal.</p>
        <p style="margin:0;"><a href="${escapeHtml(memberPortalUrl())}">Open Member Portal</a></p>
      </div>`,
      `Order submitted: ${orderId}\nPortal: ${memberPortalUrl()}`
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
// MEMBER APIs
// =========================
app.get("/api/member/orders", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const items = await Order.find({ "customer.email": email })
      .sort({ createdAt: -1 })
      .limit(60)
      .lean();

    // Include cutoff info for each runKey so the portal can decide cancellation + tracking
    const runKeys = Array.from(new Set(items.map(o => o.runKey).filter(Boolean)));
    const runs = await Run.find({ runKey: { $in: runKeys } }).lean();
    const runByKey = new Map(runs.map(r => [r.runKey, r]));

    res.json({
      ok: true,
      items,
      runs: Object.fromEntries(Array.from(runByKey.entries()).map(([k, r]) => [k, {
        runKey: r.runKey,
        type: r.type,
        opensAt: r.opensAt,
        cutoffAt: r.cutoffAt,
        maxSlots: r.maxSlots,
        bookedOrdersCount: r.bookedOrdersCount,
        bookedFeesTotal: r.bookedFeesTotal,
        minOrders: r.minOrders,
        minFees: r.minFees,
        minLogic: r.minLogic,
      }])),
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/member/cancel-membership", requireLogin, async (req, res) => {
  try {
    const u = await User.findById(req.user._id);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    // NOTE: This cancels membership status inside TGR only.
    // Payment-link billing (if any) must be canceled in Square by the customer/admin.
    u.membershipLevel = "none";
    u.membershipStatus = "inactive";
    u.renewalDate = null;
    await u.save();

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Mint a tracking token for an order (member-only).
// The live fix still requires Tracking.enabled=true and driver pings stored in Tracking doc.
app.get("/api/member/tracking-token", requireLogin, async (req, res) => {
  try {
    const orderId = String(req.query.orderId || "").trim().toUpperCase();
    if (!orderId) return res.status(400).json({ ok: false, error: "Missing orderId" });

    const email = String(req.user?.email || "").toLowerCase().trim();
    const order = await Order.findOne({ orderId, "customer.email": email }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const state = order?.status?.state || "submitted";
    if (!ACTIVE_STATES.has(state)) {
      return res.status(403).json({ ok: false, error: "Tracking only available for active orders." });
    }

    const runKey = order.runKey;
    const expMs = Date.now() + 1000 * 60 * 60 * 24; // 24h token
    const token = signTrackingToken(orderId, runKey, expMs);

    res.json({ ok: true, orderId, runKey, token, mapboxPublicToken: MAPBOX_PUBLIC_TOKEN || "" });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// MEMBER PORTAL (FULL PAGE)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  try {
    const u = await User.findById(req.user._id).lean();
    const email = String(u?.email || "").toLowerCase().trim();
    const name = String(u?.name || "").trim();

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGR Member Portal</title>
<link href="https://api.mapbox.com/mapbox-gl-js/v3.6.0/mapbox-gl.css" rel="stylesheet">
<script src="https://api.mapbox.com/mapbox-gl-js/v3.6.0/mapbox-gl.js"></script>
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
  #map{height:380px;border-radius:12px;border:1px solid rgba(255,255,255,.12);overflow:hidden;}
  .kpi{display:flex;gap:10px;flex-wrap:wrap;}
  .kpi .box{border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.22);border-radius:12px;padding:10px 12px;}
  .kpi .label{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;}
  .kpi .value{font-weight:1000;font-size:18px;margin-top:4px;}
  .small{font-size:12px;}
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

    <div class="kpi">
      <div class="box">
        <div class="label">Membership</div>
        <div class="value" id="mLevel">—</div>
        <div class="muted small" id="mMeta">—</div>
      </div>
      <div class="box">
        <div class="label">Renewal</div>
        <div class="value" id="mRenew">—</div>
        <div class="muted small">Auto-updated from Square payments when email matches.</div>
      </div>
      <div class="box">
        <div class="label">Actions</div>
        <div class="row" style="margin-top:6px;">
          <a class="btn" id="buyStandard" target="_blank" rel="noopener">Buy Standard</a>
          <a class="btn" id="buyRoute" target="_blank" rel="noopener">Buy Route</a>
          <a class="btn" id="buyAccess" target="_blank" rel="noopener">Buy Access</a>
          <a class="btn" id="buyAccessPro" target="_blank" rel="noopener">Buy Access Pro</a>
          <button class="btn ghost" id="cancelMembershipBtn" type="button">Cancel membership (in portal)</button>
        </div>
        <div class="muted small" style="margin-top:8px;">
          Note: Payment-link subscriptions (if any) must be canceled in Square separately.
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div style="font-weight:1000;font-size:18px;">Live Tracking</div>
    <div class="muted">Tracking appears when your order is active and the run’s tracking is enabled.</div>
    <div class="row" style="margin-top:10px;">
      <select id="trackOrderSelect" style="padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.25);color:#fff;min-width:320px;">
        <option value="">Select an active order…</option>
      </select>
      <button class="btn primary" id="startTrackBtn" type="button">Load Map</button>
      <span class="muted small" id="trackHint"></span>
    </div>
    <div style="margin-top:12px;">
      <div id="map"></div>
    </div>

    <div class="hr"></div>

    <div style="font-weight:1000;font-size:18px;">Order History</div>
    <div class="muted">Shows up to your most recent 60 orders.</div>

    <div style="overflow:auto;margin-top:10px;">
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Address</th>
            <th>Run</th>
            <th>Status</th>
            <th>Fees</th>
            <th>Cancel</th>
          </tr>
        </thead>
        <tbody id="rows">
          <tr><td colspan="6" class="muted">Loading…</td></tr>
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

  const LINKS = {
    standard: "${escapeHtml(SQUARE_LINK_STANDARD)}",
    route: "${escapeHtml(SQUARE_LINK_ROUTE)}",
    access: "${escapeHtml(SQUARE_LINK_ACCESS)}",
    accesspro: "${escapeHtml(SQUARE_LINK_ACCESSPRO)}"
  };

  document.getElementById("buyStandard").href = LINKS.standard;
  document.getElementById("buyRoute").href = LINKS.route;
  document.getElementById("buyAccess").href = LINKS.access;
  document.getElementById("buyAccessPro").href = LINKS.accesspro;

  async function loadMe(){
    const r = await fetch("/api/me", { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Me failed");

    document.getElementById("mLevel").textContent = (d.membershipLevel || "none").toUpperCase();
    document.getElementById("mMeta").textContent = "Status: " + (d.membershipStatus || "inactive");
    document.getElementById("mRenew").textContent = d.renewalDate ? String(d.renewalDate) : "—";
  }

  function fmtMoney(n){
    const x = Number(n || 0);
    return "$" + x.toFixed(2);
  }

  function fmtDate(d){
    try{ return new Date(d).toLocaleString(); } catch { return ""; }
  }

  async function cancelMembership(){
    const ok = confirm("Cancel membership in portal? (Square billing is separate for payment links.)");
    if(!ok) return;
    const r = await fetch("/api/member/cancel-membership", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({})
    });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Cancel failed");
    toast("Membership cancelled in portal.");
    loadMe().catch(()=>{});
  }

  document.getElementById("cancelMembershipBtn").addEventListener("click", cancelMembership);

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
    await loadOrders();
  }

  let runsByKey = {};
  let activeOrders = [];
  let map = null;
  let marker = null;
  let pollTimer = null;
  let currentTrack = { runKey:"", token:"" };

  async function loadOrders(){
    const r = await fetch("/api/member/orders", { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) throw new Error(d.error || "Orders failed");

    runsByKey = d.runs || {};
    const items = d.items || [];

    // Active orders for tracking
    const ACTIVE = new Set(["submitted","confirmed","shopping","packed","out_for_delivery"]);
    activeOrders = items.filter(o => ACTIVE.has(o.status?.state || "submitted"));

    // populate tracking select
    const sel = document.getElementById("trackOrderSelect");
    sel.innerHTML = '<option value="">Select an active order…</option>';
    activeOrders.forEach(o=>{
      const opt = document.createElement("option");
      opt.value = o.orderId;
      opt.textContent = o.orderId + " • " + (o.address?.town || "") + " • " + (o.status?.state || "");
      sel.appendChild(opt);
    });

    const tbody = document.getElementById("rows");
    tbody.innerHTML = "";

    const now = Date.now();

    items.forEach(o=>{
      const run = runsByKey[o.runKey] || null;
      const cutoffMs = run?.cutoffAt ? new Date(run.cutoffAt).getTime() : 0;
      const cancelOpen = cutoffMs ? (now < cutoffMs) : false;

      const fees = (o.pricingSnapshot && typeof o.pricingSnapshot.totalFees === "number") ? o.pricingSnapshot.totalFees : 0;
      const status = o.status?.state || "submitted";

      let cancelHtml = '<span class="muted">Not available</span>';
      if (ACTIVE.has(status) && cancelOpen){
        // token created server-side? Your /api/orders returns cancelToken at submit time,
        // but portal can’t know it. We keep "not available" unless you store token.
        // Instead: show "Past cutoff" or "Use confirmation link".
        cancelHtml = '<span class="muted">Use your order confirmation cancel link</span>';
      } else if (status === "cancelled") {
        cancelHtml = '<span class="pill">Cancelled</span>';
      } else if (!cancelOpen && ACTIVE.has(status)) {
        cancelHtml = '<span class="muted">Past cutoff</span>';
      }

      const tr = document.createElement("tr");
      tr.innerHTML = \`
        <td><div style="font-weight:1000;">\${o.orderId}</div><div class="muted small">\${fmtDate(o.createdAt)}</div></td>
        <td><div style="font-weight:900;">\${(o.address?.town||"")} (Zone \${(o.address?.zone||"")})</div>
            <div class="muted small">\${(o.address?.streetAddress||"")} • \${(o.address?.postalCode||"")}</div></td>
        <td><span class="pill">\${(o.runType||"")}</span><div class="muted small">\${(o.runKey||"")}</div></td>
        <td><span class="pill">\${status}</span><div class="muted small">\${(o.status?.note||"")}</div></td>
        <td>\${fmtMoney(fees)}</td>
        <td>\${cancelHtml}</td>
      \`;
      tbody.appendChild(tr);
    });

    if (!items.length){
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No orders yet.</td></tr>';
    }
  }

  async function initMapIfNeeded(token){
    // fetch mapbox token from server
    const r = await fetch("/api/public/config", { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    const mb = d.mapboxPublicToken || "";
    if(!mb) { toast("Mapbox token missing on server."); return null; }

    mapboxgl.accessToken = mb;

    if (!map){
      map = new mapboxgl.Map({
        container: "map",
        style: "mapbox://styles/mapbox/streets-v12",
        center: [-81.66, 45.25],
        zoom: 9
      });
      map.addControl(new mapboxgl.NavigationControl(), "top-right");
    }
    return mb;
  }

  async function pollTracking(){
    if(!currentTrack.runKey || !currentTrack.token) return;

    const url = "/api/public/tracking/" + encodeURIComponent(currentTrack.runKey) + "?token=" + encodeURIComponent(currentTrack.token);
    const r = await fetch(url, { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false){
      document.getElementById("trackHint").textContent = d.error || "Tracking unavailable.";
      return;
    }

    if(!d.enabled){
      document.getElementById("trackHint").textContent = "Tracking is not enabled for this run yet.";
      return;
    }
    if(!d.hasFix){
      document.getElementById("trackHint").textContent = "Tracking enabled — waiting for GPS fix…";
      return;
    }

    document.getElementById("trackHint").textContent = "Live tracking active • last update: " + fmtDate(d.last.at);

    const lng = Number(d.last.lng);
    const lat = Number(d.last.lat);
    if(!Number.isFinite(lng) || !Number.isFinite(lat)) return;

    if (!marker){
      marker = new mapboxgl.Marker({ color: "#ff4a44" }).setLngLat([lng, lat]).addTo(map);
      map.flyTo({ center:[lng, lat], zoom: 11 });
    } else {
      marker.setLngLat([lng, lat]);
    }
  }

  async function startTracking(){
    const orderId = document.getElementById("trackOrderSelect").value;
    if(!orderId) return toast("Select an active order first.");

    await initMapIfNeeded();

    const r = await fetch("/api/member/tracking-token?orderId=" + encodeURIComponent(orderId), { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if(!r.ok || d.ok===false) return toast(d.error || "Could not start tracking.");

    currentTrack.runKey = d.runKey;
    currentTrack.token = d.token;

    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollTracking, 5000);
    await pollTracking();
  }

  document.getElementById("startTrackBtn").addEventListener("click", startTracking);

  // Boot
  Promise.resolve()
    .then(loadMe)
    .then(loadOrders)
    .catch(e=>toast(String(e.message||e)));
</script>

</body>
</html>`);
  } catch (e) {
    res.status(500).send("Member portal error: " + String(e));
  }
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