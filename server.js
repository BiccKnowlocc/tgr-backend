// ======= server.js (FULL CLEAN FILE) — TGR backend =======
// Adds:
// - Rich /member portal (active orders, past orders, tracking, cancel, pay buttons, membership info)
// - Member endpoints:
//    GET  /api/member/orders
//    POST /api/member/orders/:orderId/cancel-token
//    POST /api/member/membership/cancel
// Does NOT change public index styling/structure.

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");

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

const TZ = process.env.TZ || "America/Toronto";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://tobermorygroceryrun.ca";

// Square pay links (used in member portal buttons)
const SQUARE_PAY_GROCERIES_LINK = process.env.SQUARE_PAY_GROCERIES_LINK || "https://square.link/u/R0hfr7x8";
const SQUARE_PAY_FEES_LINK = process.env.SQUARE_PAY_FEES_LINK || "https://square.link/u/r92W6XGs";

// Membership links (optional)
const SQUARE_LINK_STANDARD = process.env.SQUARE_LINK_STANDARD || "https://square.link/u/iaziCZjG";
const SQUARE_LINK_ROUTE = process.env.SQUARE_LINK_ROUTE || "https://square.link/u/P5ROgqyp";
const SQUARE_LINK_ACCESS = process.env.SQUARE_LINK_ACCESS || "https://square.link/u/lHtHtvqG";
const SQUARE_LINK_ACCESSPRO = process.env.SQUARE_LINK_ACCESSPRO || "https://square.link/u/S0Y5Fysa";

const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:3000",
  "http://localhost:8888",
];

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

// Uploads (local disk)
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
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
// PRICING (SERVER TRUTH BASELINE)
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
  if (!tier || !applyPerkYes) return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false };
  if (tier === "standard") return { serviceOff: 0, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };
  if (tier === "route") return { serviceOff: 5, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false };
  if (tier === "access") return { serviceOff: 8, zoneOff: 10, freeAddonUpTo: 10, waitWaived: true };
  if (tier === "accesspro") return { serviceOff: 10, zoneOff: 0, freeAddonUpTo: 0, waitWaived: true };
  return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false };
}

// =========================
// MONGO MODELS (IN FILE)
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
    address: { town: String, streetAddress: String, zone: { type: String, enum: ["A", "B", "C", "D"] } },
    stores: { primary: String, extra: [String] },
    preferences: { dropoffPref: String, subsPref: String, contactPref: String, contactAuth: Boolean },

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
      fees: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null } },
      groceries: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null } },
    },

    status: {
      state: { type: String, enum: AllowedStates, default: "submitted" },
      note: { type: String, default: "" },
      updatedAt: { type: Date, default: Date.now },
      updatedBy: { type: String, default: "system" },
    },

    statusHistory: {
      type: [
        { state: { type: String, enum: AllowedStates }, note: String, at: Date, by: String },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);

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

function nowTz() { return dayjs().tz(TZ); }
function fmtLocal(d) { if (!d) return ""; return dayjs(d).tz(TZ).format("ddd MMM D, h:mma"); }

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
    const delivery = nextDow(6, base);
    const cutoff = delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0);
    const opens = delivery.subtract(5, "day").hour(0).minute(0).second(0).millisecond(0);
    return { delivery, cutoff, opens };
  }
  const delivery = nextDow(0, base);
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

    const needsRecalc = !run.lastRecalcAt || dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(60, "second").toDate());
    if (needsRecalc) {
      const agg = await Order.aggregate([
        { $match: { runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } } },
        { $group: { _id: "$runKey", c: { $sum: 1 }, fees: { $sum: "$pricingSnapshot.totalFees" } } },
      ]);

      const c = agg?.[0]?.c || 0;
      const fees = agg?.[0]?.fees || 0;

      await Run.updateOne({ runKey }, { $set: { bookedOrdersCount: c, bookedFeesTotal: fees, lastRecalcAt: new Date() } });
      run.bookedOrdersCount = c;
      run.bookedFeesTotal = fees;
      run.lastRecalcAt = new Date();
    }

    out[type] = run;
  }
  return out;
}

async function nextOrderId() {
  const c = await Counter.findOneAndUpdate({ key: "orders" }, { $inc: { seq: 1 } }, { upsert: true, new: true }).lean();
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
  if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) surcharges += PRICING.groceryUnderMin.surcharge;

  const serviceOff = Math.min(serviceFee, disc.serviceOff || 0);
  const optionA = Math.min(zoneFee, disc.zoneOff || 0);
  const optionB = Math.min(addOnsFees + runFee, disc.freeAddonUpTo || 0);
  const bestOr = Math.max(optionA, optionB);
  const discount = serviceOff + bestOr;

  const totalFees = Math.max(0, serviceFee + zoneFee + runFee + addOnsFees + surcharges - discount);

  return { totals: { serviceFee, zoneFee, runFee, addOnsFees, surcharges, discount, totalFees } };
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

function yn(v) {
  return v === true || String(v || "").toLowerCase() === "yes";
}

// =========================
// AUTH ROUTES
// =========================
app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
    return res.status(500).send("Google auth is not configured on this server.");
  }
  req.session.returnTo = String(req.query.returnTo || PUBLIC_SITE_URL + "/").trim();
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
// ORDERS (customer)
// =========================
app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};
    const user = await User.findById(req.user._id).lean();
    const profile = user?.profile || {};

    if (!yn(b.consent_terms) || !yn(b.consent_accuracy) || !yn(b.consent_dropoff)) {
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    const required = ["town","streetAddress","zone","runType","primaryStore","groceryList","dropoffPref","subsPref","contactPref"];
    for (const k of required) {
      if (!String(b[k] || "").trim()) return res.status(400).json({ ok: false, error: "Missing required field: " + k });
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

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    await Order.create({
      orderId,
      runKey: run.runKey,
      runType,
      customer: {
        fullName: String(profile.fullName || user.name || "").trim(),
        email: String(user.email || "").trim().toLowerCase(),
        phone: String(profile.phone || "").trim(),
      },
      address: { town: String(b.town || "").trim(), streetAddress: String(b.streetAddress || "").trim(), zone: String(b.zone || "") },
      stores: { primary: String(b.primaryStore || "").trim(), extra: extraStores },
      preferences: { dropoffPref: String(b.dropoffPref || ""), subsPref: String(b.subsPref || ""), contactPref: String(b.contactPref || ""), contactAuth: true },
      list: { groceryListText: String(b.groceryList || "").trim(), attachment },
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
        stores: order.stores,
        address: order.address,
        pricingSnapshot: order.pricingSnapshot,
        payments: order.payments,
        status: { state: order.status?.state || "submitted", note: order.status?.note || "", updatedAtLocal: fmtLocal(order.status?.updatedAt || order.updatedAt) },
        statusHistory: (order.statusHistory || []).map((h) => ({ state: h.state, note: h.note || "", atLocal: fmtLocal(h.at), by: h.by || "system" })),
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
      return res.status(403).json({ ok: false, error: "Cancellation window closed (past cutoff). After-cutoff policy applies." });
    }

    const fees = Number(order.pricingSnapshot?.totalFees || 0);
    await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } });

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
// MEMBER API (NEW)
// =========================
app.get("/api/member/orders", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const items = await Order.find({ "customer.email": email }).sort({ createdAt: -1 }).limit(50).lean();

    // Split active vs history
    const active = [];
    const history = [];
    for (const o of items) {
      const st = o.status?.state || "submitted";
      const entry = {
        orderId: o.orderId,
        runKey: o.runKey,
        runType: o.runType,
        createdAtLocal: fmtLocal(o.createdAt),
        customerName: o.customer?.fullName || "",
        town: o.address?.town || "",
        zone: o.address?.zone || "",
        streetAddress: o.address?.streetAddress || "",
        primaryStore: o.stores?.primary || "",
        status: { state: st, note: o.status?.note || "", updatedAtLocal: fmtLocal(o.status?.updatedAt || o.updatedAt) },
        pricingSnapshot: { totalFees: Number(o.pricingSnapshot?.totalFees || 0) },
        payments: {
          fees: { status: o.payments?.fees?.status || "unpaid" },
          groceries: { status: o.payments?.groceries?.status || "unpaid" },
        },
      };
      if (ACTIVE_STATES.has(st)) active.push(entry);
      else history.push(entry);
    }

    res.json({ ok: true, active, history });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Mint a cancel token for the logged-in user’s own order (so member portal can cancel without localStorage token)
app.post("/api/member/orders/:orderId/cancel-token", requireLogin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const email = String(req.user?.email || "").toLowerCase().trim();

    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    if (String(order.customer?.email || "").toLowerCase().trim() !== email) {
      return res.status(403).json({ ok: false, error: "Not authorized for this order" });
    }

    const st = order.status?.state || "submitted";
    if (!ACTIVE_STATES.has(st)) return res.status(400).json({ ok: false, error: "Order is not cancellable in its current status" });

    const run = await Run.findOne({ runKey: order.runKey }).lean();
    if (!run?.cutoffAt) return res.status(500).json({ ok: false, error: "Run cutoff not available" });

    const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    const now = nowTz();
    if (!now.isBefore(cutoffAt)) {
      return res.status(403).json({ ok: false, error: "Cancellation window closed (past cutoff)" });
    }

    const cancelUntilMs = cutoffAt.toDate().getTime();
    const cancelToken = signCancelToken(orderId, cancelUntilMs);
    const cancelUntilLocal = fmtLocal(cutoffAt.toDate());

    res.json({ ok: true, cancelToken, cancelUntilLocal });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Database-side membership cancellation request (does not cancel Square billing automatically)
app.post("/api/member/membership/cancel", requireLogin, async (req, res) => {
  try {
    const u = await User.findById(req.user._id);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    u.membershipStatus = "cancelled";
    u.membershipLevel = "none";
    u.renewalDate = null;
    await u.save();

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// MEMBER PORTAL (UPGRADED)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  const email = String(u?.email || "").toLowerCase();

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>TGR Member Portal</title>
<style>
  :root{
    --black:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14);
    --text:#fff; --muted:rgba(255,255,255,.78); --red:#e3342f; --red2:#ff4a44;
    --radius:16px;
  }
  body{
    margin:0; background:
      radial-gradient(900px 500px at 20% 0%, rgba(227,52,47,.22), transparent 55%),
      linear-gradient(180deg, #0f0f10, var(--black));
    color:var(--text);
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
    padding:14px;
  }
  a{ color:#fff; }
  .wrap{ max-width:1100px; margin:0 auto; }
  .card{ border:1px solid var(--line); background:var(--panel); border-radius:var(--radius); padding:14px; box-shadow: 0 14px 46px rgba(0,0,0,.35); }
  .row{ display:flex; gap:12px; flex-wrap:wrap; }
  .col{ flex: 1 1 280px; min-width: 260px; }
  .btn{
    border:1px solid rgba(255,255,255,.18);
    background:rgba(255,255,255,.06);
    color:#fff; font-weight:900;
    border-radius:999px;
    padding:12px 14px;
    cursor:pointer;
    text-decoration:none;
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:10px;
    white-space:nowrap;
  }
  .btn.primary{ background:linear-gradient(180deg,var(--red2),var(--red)); border-color:rgba(0,0,0,.25); }
  .btn.secondary{ background:rgba(217,217,217,.10); border-color:rgba(217,217,217,.22); }
  .btn.ghost{ background:transparent; }
  .muted{ color:var(--muted); }
  h1{ margin:0 0 8px; font-size:26px; }
  h2{ margin:0 0 8px; font-size:20px; }
  .pill{ display:inline-block; padding:4px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.18); background:rgba(255,255,255,.06); font-weight:900; font-size:12px; }
  .hr{ height:1px; background:rgba(255,255,255,.12); margin:12px 0; }
  table{ width:100%; border-collapse:collapse; }
  th,td{ padding:10px 8px; border-bottom:1px solid rgba(255,255,255,.12); vertical-align:top; }
  th{ font-size:12px; color:rgba(255,255,255,.72); text-transform:uppercase; letter-spacing:.08em; text-align:left; }
  .toast{ margin-top:10px; padding:10px 12px; border-radius:12px; border:1px solid rgba(255,255,255,.18); background:rgba(0,0,0,.24); display:none; font-weight:900; }
  .toast.show{ display:block; }
  @media(max-width:820px){
    .btn{ width:100%; }
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="align-items:center; justify-content:space-between;">
      <div>
        <h1>Member Portal</h1>
        <div class="muted">Signed in as <strong>${escapeHtml(email)}</strong></div>
      </div>
      <div class="row">
        <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
        <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
      </div>
    </div>

    <div class="toast" id="toast"></div>

    <div class="hr"></div>

    <div class="row">
      <div class="col card" style="background:rgba(0,0,0,.20); box-shadow:none;">
        <h2>Membership</h2>
        <div class="muted">Status and quick actions.</div>
        <div class="hr"></div>
        <div><strong>Plan:</strong> <span id="mPlan">…</span></div>
        <div><strong>Status:</strong> <span id="mStatus">…</span></div>
        <div><strong>Renewal:</strong> <span id="mRenewal">…</span></div>

        <div class="hr"></div>

        <div class="row">
          <a class="btn primary" id="btnBuyMembership" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=membership">Buy / Change Plan</a>
          <button class="btn secondary" id="btnCancelMembership" type="button">Cancel membership</button>
        </div>

        <div class="muted" style="font-size:13px; margin-top:10px;">
          Note: cancelling here updates your TGR account status. If Square billing is ever enabled as a true subscription,
          you’ll also cancel there. For now, contact support if anything looks wrong.
        </div>
      </div>

      <div class="col card" style="background:rgba(0,0,0,.20); box-shadow:none;">
        <h2>Payments</h2>
        <div class="muted">Use these links and paste your Order ID in the Square note.</div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn primary" href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}" target="_blank" rel="noopener">Pay Grocery Total</a>
          <a class="btn secondary" href="${escapeHtml(SQUARE_PAY_FEES_LINK)}" target="_blank" rel="noopener">Pay Service & Delivery Fees</a>
        </div>
        <div class="hr"></div>
        <div class="muted" style="font-size:13px;">
          Tip: If you paid and it still shows unpaid, message support with the Order ID and payment timestamp.
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="card" style="background:rgba(0,0,0,.20); box-shadow:none;">
      <h2>Active orders</h2>
      <div class="muted">Live view of orders that are in progress.</div>
      <div class="hr"></div>
      <div id="activeWrap" class="muted">Loading…</div>
    </div>

    <div class="hr"></div>

    <div class="card" style="background:rgba(0,0,0,.20); box-shadow:none;">
      <h2>Order history</h2>
      <div class="muted">Your most recent orders.</div>
      <div class="hr"></div>
      <div style="overflow:auto;">
        <table>
          <thead>
            <tr>
              <th>Order</th>
              <th>Created</th>
              <th>Run</th>
              <th>Status</th>
              <th>Fees</th>
              <th>Payments</th>
              <th>Track</th>
            </tr>
          </thead>
          <tbody id="histRows"></tbody>
        </table>
      </div>
      <div class="muted" style="margin-top:10px; font-size:13px;">
        Want full tracking? It’s coming. This portal already mirrors what the system knows about each order (status + payment flags).
      </div>
    </div>

  </div>
</div>

<script>
  const API_ME = "/api/me";
  const API_MEMBER_ORDERS = "/api/member/orders";
  const API_CANCEL_TOKEN = (id) => "/api/member/orders/" + encodeURIComponent(id) + "/cancel-token";
  const API_CANCEL = (id) => "/api/orders/" + encodeURIComponent(id) + "/cancel";
  const API_TRACK = (id) => "/api/orders/" + encodeURIComponent(id);
  const API_CANCEL_MEMBERSHIP = "/api/member/membership/cancel";

  const toast = (msg) => {
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(()=> el.classList.remove("show"), 4500);
  };

  function nicePlan(p){
    const s = String(p||"none");
    if(s==="none") return "None";
    if(s==="standard") return "Standard";
    if(s==="route") return "Route";
    if(s==="access") return "Access";
    if(s==="accesspro") return "Access Pro";
    return s;
  }

  async function loadMe(){
    const r = await fetch(API_ME, { credentials:"include" });
    const data = await r.json().catch(()=>({}));
    if(!r.ok || data.ok === false) throw new Error(data.error || "ME failed");
    document.getElementById("mPlan").textContent = nicePlan(data.membershipLevel);
    document.getElementById("mStatus").textContent = String(data.membershipStatus||"inactive");
    document.getElementById("mRenewal").textContent = data.renewalDate ? new Date(data.renewalDate).toLocaleDateString() : "—";
  }

  function money(n){ const v = Number(n||0); return "$"+v.toFixed(2); }

  async function loadOrders(){
    const r = await fetch(API_MEMBER_ORDERS, { credentials:"include" });
    const data = await r.json().catch(()=>({}));
    if(!r.ok || data.ok === false) throw new Error(data.error || "Orders failed");

    const active = data.active || [];
    const history = data.history || [];

    // Active cards
    const aw = document.getElementById("activeWrap");
    if(!active.length){
      aw.innerHTML = "<span class='muted'>No active orders right now.</span>";
    } else {
      aw.innerHTML = active.map(o => {
        const fees = o.pricingSnapshot?.totalFees ?? 0;
        const payFees = o.payments?.fees?.status || "unpaid";
        const payGro = o.payments?.groceries?.status || "unpaid";
        const st = o.status?.state || "submitted";
        const note = o.status?.note || "";
        return \`
          <div class="card" style="background:rgba(0,0,0,.18); box-shadow:none; margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;">
              <div>
                <div style="font-weight:1000;font-size:18px;">\${o.orderId} <span class="pill">\${st}</span></div>
                <div class="muted">\${o.runType} • \${o.runKey} • \${o.createdAtLocal}</div>
                <div class="muted">\${o.town} (\${o.zone}) • \${o.streetAddress}</div>
                <div class="muted">Fees: <strong>\${money(fees)}</strong> • Fees payment: <strong>\${payFees}</strong> • Grocery payment: <strong>\${payGro}</strong></div>
                \${note ? \`<div class="muted" style="margin-top:6px;">Note: \${note}</div>\` : "" }
              </div>
              <div style="display:flex;flex-direction:column;gap:10px;min-width:220px;flex:0 0 auto;">
                <a class="btn primary" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=status" target="_blank" rel="noopener">Open Live Status</a>
                <button class="btn secondary" data-cancel="\${o.orderId}">Cancel order (if eligible)</button>
                <a class="btn ghost" href="${escapeHtml(SQUARE_PAY_FEES_LINK)}" target="_blank" rel="noopener">Pay fees</a>
              </div>
            </div>
          </div>
        \`;
      }).join("");

      aw.querySelectorAll("[data-cancel]").forEach(btn => {
        btn.addEventListener("click", async () => {
          const orderId = btn.getAttribute("data-cancel");
          const ok = confirm("Cancel " + orderId + " now? This is only allowed before cutoff.");
          if(!ok) return;
          try{
            btn.disabled = true;
            // Mint token for this member/order
            const tr = await fetch(API_CANCEL_TOKEN(orderId), { method:"POST", credentials:"include" });
            const td = await tr.json().catch(()=>({}));
            if(!tr.ok || td.ok === false) throw new Error(td.error || "Could not mint cancel token");
            const token = td.cancelToken;

            // Cancel
            const cr = await fetch(API_CANCEL(orderId), {
              method:"POST",
              headers:{ "Content-Type":"application/json" },
              credentials:"include",
              body: JSON.stringify({ token }),
            });
            const cd = await cr.json().catch(()=>({}));
            if(!cr.ok || cd.ok === false) throw new Error(cd.error || "Cancel failed");
            toast("Order cancelled ✅ " + orderId);
            await loadOrders();
          } catch(e){
            toast("Cancel error: " + String(e.message || e));
          } finally {
            btn.disabled = false;
          }
        });
      });
    }

    // History table
    const tb = document.getElementById("histRows");
    tb.innerHTML = history.map(o => {
      const fees = o.pricingSnapshot?.totalFees ?? 0;
      const payFees = o.payments?.fees?.status || "unpaid";
      const payGro = o.payments?.groceries?.status || "unpaid";
      const st = o.status?.state || "submitted";
      return \`
        <tr>
          <td style="font-weight:1000;">\${o.orderId}</td>
          <td class="muted">\${o.createdAtLocal}</td>
          <td><span class="pill">\${o.runType}</span><div class="muted" style="margin-top:4px;">\${o.runKey}</div></td>
          <td><span class="pill">\${st}</span><div class="muted" style="margin-top:4px;">\${o.status?.note || ""}</div></td>
          <td>\${money(fees)}</td>
          <td class="muted">Fees: <strong>\${payFees}</strong><br>Groceries: <strong>\${payGro}</strong></td>
          <td><a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=status" target="_blank" rel="noopener">Track</a></td>
        </tr>
      \`;
    }).join("");

    if(!history.length){
      tb.innerHTML = "<tr><td colspan='7' class='muted'>No previous orders yet.</td></tr>";
    }
  }

  document.getElementById("btnCancelMembership").addEventListener("click", async ()=>{
    const ok = confirm("Cancel your membership status in TGR? (If you have any Square billing in future, you may still need to cancel there too.)");
    if(!ok) return;
    try{
      const r = await fetch(API_CANCEL_MEMBERSHIP, { method:"POST", credentials:"include" });
      const d = await r.json().catch(()=>({}));
      if(!r.ok || d.ok === false) throw new Error(d.error || "Cancel membership failed");
      toast("Membership cancelled in TGR ✅");
      await loadMe();
    } catch(e){
      toast("Cancel membership error: " + String(e.message || e));
    }
  });

  (async ()=>{
    try{
      await loadMe();
      await loadOrders();
      // Auto-refresh active orders periodically
      setInterval(loadOrders, 20000);
    } catch(e){
      toast("Portal error: " + String(e.message || e));
    }
  })();
</script>

</body>
</html>`);
});

// =========================
// ADMIN (unchanged in this snippet)
// If your current server already has /admin and /api/admin/* from the last version, keep them.
// =========================

// Minimal admin placeholder (keep your existing full admin if already deployed)
app.get("/admin", requireLogin, requireAdmin, (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<h1>Admin</h1><p>Admin UI is already in your deployed version. Keep your existing /admin page code here.</p>`);
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