/**
 * server.js — TGR backend (Express + MongoDB + Google OAuth + Required Account Onboarding + Runs + Orders + Estimator + Pay links + Square webhook)
 *
 * REQUIRED ACCOUNT FLOW:
 * - Google login creates/updates User (email/name/photo/googleId)
 * - User must complete /api/profile (Create Account) before POST /api/orders is allowed
 * - Google callback redirects to https://tobermorygroceryrun.ca/?tab=account&onboarding=1 if incomplete
 *
 * Render ENV (minimum):
 * - MONGO_URI (or MONGODB_URI)  -> MongoDB Atlas URI
 * - SESSION_SECRET             -> long random string
 * - GOOGLE_CLIENT_ID
 * - GOOGLE_CLIENT_SECRET
 * - GOOGLE_CALLBACK_URL        -> https://api.tobermorygroceryrun.ca/auth/google/callback
 *
 * Optional:
 * - ADMIN_EMAILS (comma-separated allowlist for /admin)
 * - TZ (default America/Toronto)
 *
 * Square links (optional):
 * - SQUARE_PAY_GROCERIES_LINK
 * - SQUARE_PAY_FEES_LINK
 * - SQUARE_LINK_STANDARD
 * - SQUARE_LINK_ROUTE
 * - SQUARE_LINK_ACCESS
 * - SQUARE_LINK_ACCESSPRO
 *
 * Square webhook (optional):
 * - SQUARE_WEBHOOK_SIGNATURE_KEY
 * - SQUARE_WEBHOOK_NOTIFICATION_URL -> https://api.tobermorygroceryrun.ca/webhooks/square
 * - SQUARE_ACCESS_TOKEN
 * - SQUARE_PLAN_STANDARD_VARIATION_ID
 * - SQUARE_PLAN_ROUTE_VARIATION_ID
 * - SQUARE_PLAN_ACCESS_VARIATION_ID
 * - SQUARE_PLAN_ACCESSPRO_VARIATION_ID
 */

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");

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

// Frontend domains allowed to send cookies to API
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

const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL = process.env.SQUARE_WEBHOOK_NOTIFICATION_URL || "";
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";

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

// Capture rawBody for Square webhook signature validation
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

// Render/proxy support for secure cookies
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
// UPLOADS
// =========================
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 },
});

// =========================
// PRICING (SERVER TRUTH)
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
// MONGO MODELS (LOCAL TO SERVER.JS)
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

const WebhookEventSchema = new mongoose.Schema(
  { eventId: { type: String, unique: true, index: true }, type: { type: String, default: "" } },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);
const WebhookEvent = mongoose.model("WebhookEvent", WebhookEventSchema);

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

  // Must also have accepted required profile consents
  const consentsOk = p.consentTerms === true && p.consentPrivacy === true;

  return !!fullName && !!phone && !!contactPref && contactAuth && hasAddress && consentsOk;
}

// =========================
// GUARDS
// =========================
function requireLogin(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "Sign-in required." });
  next();
}

function requireProfileComplete(req, res, next) {
  const profile = req.user?.profile || {};
  if (!isProfileComplete(profile)) {
    return res.status(403).json({ ok: false, error: "Account setup required. Please complete your profile." });
  }
  next();
}

function requireAdmin(req, res, next) {
  const email = String(req.user?.email || "").toLowerCase();
  if (!email) return res.status(403).send("Admin access required.");
  if (ADMIN_EMAILS.length && !ADMIN_EMAILS.includes(email)) return res.status(403).send("Admin access required.");
  next();
}

// =========================
// AUTH ROUTES
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
  async (req, res) => {
    const rt = req.session.returnTo || "https://tobermorygroceryrun.ca/";
    delete req.session.returnTo;

    // Force onboarding redirect if profile incomplete
    try {
      const u = await User.findById(req.user._id).lean();
      if (!isProfileComplete(u?.profile || {})) {
        return res.redirect("https://tobermorygroceryrun.ca/?tab=account&onboarding=1");
      }
    } catch {
      // ignore and continue
    }

    res.redirect(rt);
  }
);

app.get("/logout", (req, res) => {
  const returnTo = String(req.query.returnTo || "https://tobermorygroceryrun.ca/").trim();
  req.session.destroy(() => res.redirect(returnTo));
});

// =========================
// API: ME + PROFILE
// =========================
app.get("/api/me", (req, res) => {
  const u = req.user;
  const profile = u?.profile || {};
  res.json({
    ok: true,
    loggedIn: !!u,
    email: u?.email || null,
    name: u?.name || "",
    photo: u?.photo || "",
    membershipLevel: u?.membershipLevel || "none",
    membershipStatus: u?.membershipStatus || "inactive",
    renewalDate: u?.renewalDate || null,
    profileComplete: isProfileComplete(profile),
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

    const profile = (u.profile && typeof u.profile === "object") ? u.profile : { version: 1 };

    // Identity + contact (required)
    profile.fullName = String(b.fullName || "").trim();
    profile.preferredName = String(b.preferredName || "").trim();
    profile.phone = String(b.phone || "").trim();
    profile.altPhone = String(b.altPhone || "").trim();
    profile.contactPref = String(b.contactPref || "").trim(); // call/text/email
    profile.contactAuth = String(b.contactAuth || "") === "yes";

    // Defaults / preferences (optional)
    profile.subsDefault = String(b.subsDefault || "").trim();
    profile.dropoffDefault = String(b.dropoffDefault || "").trim();
    profile.notes = String(b.notes || "").trim();
    profile.accessibility = String(b.accessibility || "").trim();
    profile.dietary = String(b.dietary || "").trim();
    profile.emergencyContactName = String(b.emergencyContactName || "").trim();
    profile.emergencyContactPhone = String(b.emergencyContactPhone || "").trim();

    // Addresses (required: at least one with street/town/zone)
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

    // Required consents for account completion
    profile.consentTerms = String(b.consentTerms || "") === "yes";
    profile.consentPrivacy = String(b.consentPrivacy || "") === "yes";
    profile.consentMarketing = String(b.consentMarketing || "") === "yes";

    // Completion
    profile.complete = isProfileComplete(profile);
    profile.completedAt = profile.complete ? (profile.completedAt || new Date().toISOString()) : (profile.completedAt || null);

    u.profile = profile;
    await u.save();

    return res.json({ ok: true, profileComplete: profile.complete === true, profile: u.profile });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// HEALTH
// =========================
app.get("/health", (_req, res) => res.json({ ok: true, uptime: process.uptime() }));

// =========================
// PAY + MEMBERSHIP CHECKOUT LINK RESOLVERS
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

app.get("/pay/groceries", (_req, res) => {
  const url = SQUARE_PAY_LINKS.groceries;
  if (!url) return res.status(500).send("Payment link not configured (SQUARE_PAY_GROCERIES_LINK).");
  res.redirect(url);
});

app.get("/pay/fees", (_req, res) => {
  const url = SQUARE_PAY_LINKS.fees;
  if (!url) return res.status(500).send("Payment link not configured (SQUARE_PAY_FEES_LINK).");
  res.redirect(url);
});

// =========================
// RUNS
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

// =========================
// FEE ESTIMATOR
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
// ORDERS (REQUIRES LOGIN + PROFILE COMPLETE)
// =========================
app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};
    const user = await User.findById(req.user._id).lean();
    const profile = user?.profile || {};

    // Per-order consents
    if (
      String(b.consent_terms || "") !== "yes" ||
      String(b.consent_accuracy || "") !== "yes" ||
      String(b.consent_dropoff || "") !== "yes"
    ) {
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    // Required order fields
    const required = ["town","streetAddress","zone","runType","primaryStore","groceryList","dropoffPref","subsPref","contactPref"];
    for (const k of required) {
      const v = String(b[k] || "").trim();
      if (!v) return res.status(400).json({ ok: false, error: "Missing required field: " + k });
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

      // Source of truth: account profile
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

    // Slot reservation
    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedOrdersCount: { $lt: maxSlots } },
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees }, $set: { lastRecalcAt: new Date() } },
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    try {
      await Order.create(orderDoc);
    } catch (e) {
      // rollback slot count if create fails
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

// Public tracking endpoint
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
// MEMBER PAGE (simple)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
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

  const complete = isProfileComplete(u?.profile || {});
  const banner = complete
    ? `<div style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;background:#f7fff8;margin-bottom:14px;"><strong>Account:</strong> complete ✅</div>`
    : `<div style="padding:12px 14px;border:1px solid #f2c2c2;border-radius:12px;background:#fff7f7;margin-bottom:14px;"><strong>Account:</strong> incomplete. Complete setup on the main site to place orders.</div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Member Portal</title></head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:1100px;margin:0 auto;">
<h1 style="margin:0 0 6px;">Member Portal</h1>
<div style="color:#444;margin-bottom:14px;">Signed in as <strong>${escapeHtml(email)}</strong></div>
${banner}

<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
<a href="https://tobermorygroceryrun.ca/" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Back to site</a>
<a href="/pay/groceries" style="padding:12px 14px;border:1px solid #e3342f;background:#e3342f;color:#fff;border-radius:12px;text-decoration:none;font-weight:900;">Pay Grocery Total</a>
<a href="/pay/fees" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Pay Service & Delivery Fees</a>
<a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F" style="padding:12px 14px;border:1px solid #ddd;border-radius:12px;text-decoration:none;color:#111;font-weight:900;">Log out</a>
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
</tr></thead>
<tbody>${rows || `<tr><td colspan="6" style="padding:10px 8px;color:#666;">No orders yet.</td></tr>`}</tbody>
</table>
</body></html>`);
});

// =========================
// ADMIN PAGE (simple placeholder)
// =========================
app.get("/admin", requireLogin, requireAdmin, async (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TGR Admin</title></head>
<body style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:18px;max-width:900px;margin:0 auto;">
<h1 style="margin:0 0 8px;">Admin</h1>
<div style="color:#444;margin-bottom:14px;">This is a placeholder admin page.</div>
<div><a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Log out</a></div>
</body></html>`);
});

// =========================
// SQUARE WEBHOOK (OPTIONAL)
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

    if (eventId) {
      const exists = await WebhookEvent.findOne({ eventId }).lean();
      if (exists) return res.status(200).send("ok");
      await WebhookEvent.create({ eventId, type: eventType });
    }

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
      (sqStatus === "PAUSED") ? "inactive" : "inactive";

    const renewalDate = subscription.charged_through_date ? new Date(subscription.charged_through_date) : null;

    let user = await User.findOne({ "profile.squareCustomerId": customerId });

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