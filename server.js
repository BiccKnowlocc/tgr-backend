// ======= server.js (FULL CLEAN FILE) — TGR backend =======
// Changes in this version:
// - Restored functional /admin UI (search + quick actions)
// - Added minimal admin API endpoints to support those actions
// No other functional changes beyond enabling the admin controls.

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
  req.session.returnTo = String(req.query.returnTo || "https://tobermorygroceryrun.ca/").trim();
  return passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "https://tobermorygroceryrun.ca/?login=failed" }),
  async (req, res) => {
    const rt = req.session.returnTo || "https://tobermorygroceryrun.ca/";
    delete req.session.returnTo;
    try {
      const u = await User.findById(req.user._id).lean();
      if (!isProfileComplete(u?.profile || {})) {
        return res.redirect("https://tobermorygroceryrun.ca/?tab=account&onboarding=1");
      }
    } catch {}
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

    const created = await Order.create({
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
// ADMIN API (restored)
// =========================
app.get("/api/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const q = String(req.query.q || "").trim();
    const state = String(req.query.state || "").trim();

    const filter = {};
    if (q) {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [
        { orderId: re },
        { "customer.fullName": re },
        { "customer.email": re },
        { "customer.phone": re },
        { "address.town": re },
        { "address.streetAddress": re },
      ];
    }
    if (state) filter["status.state"] = state;

    const items = await Order.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const state = String(req.body?.state || "").trim();
    const note = String(req.body?.note || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    if (!AllowedStates.includes(state)) return res.status(400).json({ ok: false, error: "Invalid state" });

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.status.state = state;
    order.status.note = note || "";
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state, note: note || "", at: new Date(), by });

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/cancel", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const reason = String(req.body?.reason || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    const fees = Number(order.pricingSnapshot?.totalFees || 0);

    if (wasActive) {
      await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } });
    }

    order.status.state = "cancelled";
    order.status.note = reason || "Cancelled by admin";
    order.status.updatedAt = new Date();
    order.status.updatedBy = by;
    order.statusHistory.push({ state: "cancelled", note: reason || "Cancelled by admin", at: new Date(), by });

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

app.delete("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const wasActive = ACTIVE_STATES.has(order.status?.state || "submitted");
    const fees = Number(order.pricingSnapshot?.totalFees || 0);

    if (wasActive) {
      await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -fees }, $set: { lastRecalcAt: new Date() } });
    }

    await Order.deleteOne({ orderId });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/payments", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const kind = String(req.body?.kind || "").trim(); // "fees" | "groceries"
    const status = String(req.body?.status || "").trim(); // unpaid|pending|paid
    const note = String(req.body?.note || "").trim();
    const by = String(req.user?.email || "admin").toLowerCase();

    if (!["fees", "groceries"].includes(kind)) return res.status(400).json({ ok: false, error: "Invalid kind" });
    if (!["unpaid", "pending", "paid"].includes(status)) return res.status(400).json({ ok: false, error: "Invalid status" });

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    order.payments = order.payments || { fees: {}, groceries: {} };
    order.payments[kind] = order.payments[kind] || {};
    order.payments[kind].status = status;
    order.payments[kind].note = note || "";
    order.payments[kind].paidAt = status === "paid" ? new Date() : null;

    order.statusHistory.push({ state: order.status?.state || "submitted", note: `Payment ${kind}: ${status}${note ? " — " + note : ""}`, at: new Date(), by });

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// =========================
// MEMBER + ADMIN PAGES (SERVER-RENDERED)
// =========================
app.get("/member", requireLogin, async (req, res) => {
  const u = await User.findById(req.user._id).lean();
  const email = String(u?.email || "").toLowerCase();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Member Portal</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b0b;color:#fff;margin:0;padding:16px;}
  a{color:#fff}
  .card{border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);border-radius:14px;padding:14px;max-width:900px;margin:0 auto;}
</style>
</head>
<body>
  <div class="card">
    <h1 style="margin:0 0 10px;">Member Portal</h1>
    <div>Signed in as <strong>${escapeHtml(email)}</strong></div>
    <div style="margin-top:10px;">
      <a href="https://tobermorygroceryrun.ca/">Back to site</a> •
      <a href="/logout?returnTo=https://tobermorygroceryrun.ca/">Log out</a>
    </div>
  </div>
</body></html>`);
});

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
    .wrap{max-width:1100px;margin:0 auto;padding:16px;}
    .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
    .row{display:flex;gap:10px;flex-wrap:wrap;}
    .btn{
      border:1px solid rgba(255,255,255,.18);
      background:rgba(255,255,255,.06);
      color:#fff;font-weight:900;
      border-radius:999px;
      padding:10px 14px;
      cursor:pointer;
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
    .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;}
    .small{font-size:12px;padding:8px 10px}
    .grid{display:grid;grid-template-columns:1fr;gap:12px;}
    @media(min-width:900px){ .grid{grid-template-columns: 1fr 1fr;} }
    .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;}
    .toast.show{display:block;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="row" style="align-items:center;justify-content:space-between;">
        <div>
          <div style="font-weight:1000;font-size:22px;">Admin</div>
          <div class="muted">Signed in as <strong>${escapeHtml(email)}</strong></div>
        </div>
        <div class="row">
          <a class="btn ghost" href="https://tobermorygroceryrun.ca/">Back to site</a>
          <a class="btn ghost" href="/logout?returnTo=https://tobermorygroceryrun.ca/">Log out</a>
        </div>
      </div>

      <div class="toast" id="toast"></div>

      <div class="grid" style="margin-top:12px;">
        <div class="card" style="background:rgba(0,0,0,.22);">
          <div style="font-weight:1000;">Search orders</div>
          <div class="muted">Search by Order ID, last name, email, phone, town, address.</div>
          <div class="row" style="margin-top:10px;">
            <div style="flex:1 1 320px;">
              <input id="q" placeholder="e.g., TGR-00123 or Bullock or 519..." />
            </div>
            <div style="flex:0 0 210px;">
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
            <button class="btn primary" id="searchBtn">Search</button>
            <button class="btn" id="refreshBtn">Refresh</button>
          </div>
          <div class="muted" style="margin-top:8px;">Tip: click a row’s quick actions to update status instantly.</div>
        </div>

        <div class="card" style="background:rgba(0,0,0,.22);">
          <div style="font-weight:1000;">Quick actions</div>
          <div class="muted">Apply to the order currently selected below.</div>
          <div style="margin-top:10px;">
            <div class="muted">Selected:</div>
            <div style="font-weight:1000;font-size:18px;" id="selId">None</div>
            <div class="muted" id="selMeta" style="margin-top:4px;">Select an order row.</div>

            <div class="actions" style="margin-top:10px;">
              <button class="btn small" data-act="confirmed">Confirm</button>
              <button class="btn small" data-act="shopping">Shopping</button>
              <button class="btn small" data-act="packed">Packed</button>
              <button class="btn small" data-act="out_for_delivery">Out for delivery</button>
              <button class="btn small" data-act="delivered">Delivered</button>
              <button class="btn small" data-act="issue">Issue</button>
              <button class="btn small" data-act="cancel">Cancel</button>
              <button class="btn small" data-act="delete">Delete</button>
            </div>

            <div class="hr" style="height:1px;background:rgba(255,255,255,.12);margin:12px 0;"></div>

            <div style="font-weight:900;">Payments (manual)</div>
            <div class="muted">Use if you confirmed payment outside Square notes.</div>
            <div class="actions" style="margin-top:10px;">
              <button class="btn small" data-pay="fees" data-paystatus="paid">Fees paid</button>
              <button class="btn small" data-pay="fees" data-paystatus="unpaid">Fees unpaid</button>
              <button class="btn small" data-pay="groceries" data-paystatus="paid">Groceries paid</button>
              <button class="btn small" data-pay="groceries" data-paystatus="unpaid">Groceries unpaid</button>
            </div>
          </div>
        </div>
      </div>

      <div class="card" style="background:rgba(0,0,0,.22);margin-top:12px;">
        <div style="font-weight:1000;">Orders</div>
        <div class="muted" id="countLine" style="margin-top:6px;">Loading…</div>
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
                <th>Payments</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

<script>
  const api = {
    list: "/api/admin/orders",
    setStatus: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/status",
    cancel: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/cancel",
    del: (id) => "/api/admin/orders/" + encodeURIComponent(id),
    pay: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/payments",
  };

  let selected = null;

  const toast = (msg) => {
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(()=> el.classList.remove("show"), 3500);
  };

  function money(n){
    const v = Number(n || 0);
    return "$" + v.toFixed(2);
  }

  function setSelected(o){
    selected = o;
    document.getElementById("selId").textContent = o ? o.orderId : "None";
    document.getElementById("selMeta").textContent = o
      ? ((o.customer?.fullName || "—") + " • " + (o.address?.town || "—") + " • " + (o.runType || "—") + " " + (o.runKey || ""))
      : "Select an order row.";
  }

  async function fetchOrders(){
    const q = document.getElementById("q").value.trim();
    const state = document.getElementById("state").value;

    const url = new URL(location.origin + api.list);
    if (q) url.searchParams.set("q", q);
    if (state) url.searchParams.set("state", state);
    url.searchParams.set("limit", "80");

    const r = await fetch(url.toString(), { credentials: "include" });
    const data = await r.json().catch(()=>({}));
    if (!r.ok || data.ok === false) throw new Error(data.error || "Failed to load orders");

    const items = data.items || [];
    document.getElementById("countLine").textContent = items.length + " orders shown";
    const tbody = document.getElementById("rows");
    tbody.innerHTML = "";

    items.forEach(o => {
      const tr = document.createElement("tr");
      tr.style.cursor = "pointer";
      tr.addEventListener("click", ()=> setSelected(o));

      const fees = o.pricingSnapshot?.totalFees ?? 0;
      const payFees = o.payments?.fees?.status || "unpaid";
      const payGro = o.payments?.groceries?.status || "unpaid";

      tr.innerHTML = \`
        <td>
          <div style="font-weight:1000;">\${o.orderId}</div>
          <div class="muted" style="font-size:12px;">\${new Date(o.createdAt).toLocaleString()}</div>
        </td>
        <td>
          <div style="font-weight:900;">\${(o.customer?.fullName || "—")}</div>
          <div class="muted" style="font-size:12px;">\${(o.customer?.email || "—")} • \${(o.customer?.phone || "—")}</div>
        </td>
        <td>
          <span class="pill">\${(o.runType || "—")}</span>
          <div class="muted" style="font-size:12px;margin-top:4px;">\${(o.runKey || "—")}</div>
        </td>
        <td>
          <div style="font-weight:900;">\${(o.address?.town || "—")} (\${(o.address?.zone || "—")})</div>
          <div class="muted" style="font-size:12px;">\${(o.address?.streetAddress || "—")}</div>
        </td>
        <td>
          <span class="pill">\${(o.status?.state || "submitted")}</span>
          <div class="muted" style="font-size:12px;margin-top:4px;">\${(o.status?.note || "")}</div>
        </td>
        <td>\${money(fees)}</td>
        <td>
          <div class="muted" style="font-size:12px;">Fees: <strong>\${payFees}</strong></div>
          <div class="muted" style="font-size:12px;">Groceries: <strong>\${payGro}</strong></div>
        </td>
      \`;
      tbody.appendChild(tr);
    });

    if (!selected && items.length) setSelected(items[0]);
  }

  async function setStatus(state){
    if (!selected) return toast("Select an order first.");
    const note = "";
    const r = await fetch(api.setStatus(selected.orderId), {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      credentials: "include",
      body: JSON.stringify({ state, note }),
    });
    const data = await r.json().catch(()=>({}));
    if (!r.ok || data.ok === false) throw new Error(data.error || "Status update failed");
    toast("Status updated → " + state);
    await fetchOrders();
  }

  async function cancelOrder(){
    if (!selected) return toast("Select an order first.");
    const reason = prompt("Cancel reason (optional):", "Cancelled by admin") || "";
    const r = await fetch(api.cancel(selected.orderId), {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      credentials: "include",
      body: JSON.stringify({ reason }),
    });
    const data = await r.json().catch(()=>({}));
    if (!r.ok || data.ok === false) throw new Error(data.error || "Cancel failed");
    toast("Order cancelled");
    await fetchOrders();
  }

  async function deleteOrder(){
    if (!selected) return toast("Select an order first.");
    const ok = confirm("Delete " + selected.orderId + "? This permanently removes it.");
    if (!ok) return;
    const r = await fetch(api.del(selected.orderId), { method: "DELETE", credentials: "include" });
    const data = await r.json().catch(()=>({}));
    if (!r.ok || data.ok === false) throw new Error(data.error || "Delete failed");
    toast("Order deleted");
    selected = null;
    await fetchOrders();
  }

  async function setPayment(kind, status){
    if (!selected) return toast("Select an order first.");
    const r = await fetch(api.pay(selected.orderId), {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      credentials: "include",
      body: JSON.stringify({ kind, status, note: "" }),
    });
    const data = await r.json().catch(()=>({}));
    if (!r.ok || data.ok === false) throw new Error(data.error || "Payment update failed");
    toast(kind + " → " + status);
    await fetchOrders();
  }

  document.getElementById("searchBtn").addEventListener("click", ()=> fetchOrders().catch(e=>toast(String(e.message||e))));
  document.getElementById("refreshBtn").addEventListener("click", ()=> fetchOrders().catch(e=>toast(String(e.message||e))));
  document.getElementById("q").addEventListener("keydown", (e)=>{ if(e.key==="Enter"){ e.preventDefault(); fetchOrders().catch(err=>toast(String(err.message||err))); } });

  document.querySelectorAll("[data-act]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      try{
        const act = btn.getAttribute("data-act");
        if (act === "cancel") return await cancelOrder();
        if (act === "delete") return await deleteOrder();
        await setStatus(act);
      } catch (e){
        toast(String(e.message || e));
      }
    });
  });

  document.querySelectorAll("[data-pay]").forEach(btn=>{
    btn.addEventListener("click", async ()=>{
      try{
        const kind = btn.getAttribute("data-pay");
        const status = btn.getAttribute("data-paystatus");
        await setPayment(kind, status);
      } catch (e){
        toast(String(e.message || e));
      }
    });
  });

  fetchOrders().catch(e=>toast(String(e.message||e)));
</script>
</body></html>`);
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