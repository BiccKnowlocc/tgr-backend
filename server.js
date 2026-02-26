// ======= server.js (FULL CLEAN FILE) — TGR backend =======
// Includes:
// - Google OAuth
// - Required account onboarding (/api/profile)
// - Runs (separate local/owen slot counts)
// - Orders + cancel token
// - Mapbox tracking (Policy 2): run Start/Stop + per-order packed->delivery mode + per-order override
// - Routific Platform API integration:
//   * Push run orders to Routific (Create orders)
//   * Sync routes + timeline to store planned ETAs into orders
//
// Render env (minimum):
// - MONGO_URI or MONGODB_URI
// - SESSION_SECRET
// - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL
//
// Add for Mapbox:
// - MAPBOX_PUBLIC_TOKEN
//
// Add for Routific:
// - ROUTIFIC_WORKSPACE_ID=992814
// - ROUTIFIC_API_TOKEN=Bearer <token>
//
// Routific endpoints used (Platform API):
// - POST https://planning-service.beta.routific.com/v1/orders?workspaceId={workspaceId}  (Create orders) 4
// - GET  https://planning-service.beta.routific.com/v1/routes?workspaceId={workspaceId}&date=YYYY-MM-DD (Fetch routes) 5
// - GET  https://planning-service.beta.routific.com/v1/routes/{routeUuid}/timeline (Fetch route timeline) 6

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

const MAPBOX_PUBLIC_TOKEN = process.env.MAPBOX_PUBLIC_TOKEN || "";

// Routific
const ROUTIFIC_WORKSPACE_ID = String(process.env.ROUTIFIC_WORKSPACE_ID || "").trim();
const ROUTIFIC_API_TOKEN_RAW = String(process.env.ROUTIFIC_API_TOKEN || "").trim();
const ROUTIFIC_BASE = "https://planning-service.beta.routific.com/v1";

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

const RunLocationSchema = new mongoose.Schema(
  {
    runKey: { type: String, unique: true, index: true },
    enabled: { type: Boolean, default: false },
    enabledAt: { type: Date, default: null },
    enabledBy: { type: String, default: "" },

    lat: { type: Number, default: null },
    lng: { type: Number, default: null },
    accuracy: { type: Number, default: null },
    heading: { type: Number, default: null },
    speed: { type: Number, default: null },
    updatedAt: { type: Date, default: null },
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

    // Tracking gating
    trackingEnabled: { type: Boolean, default: false },
    trackingEnabledAt: { type: Date, default: null },
    trackingEnabledBy: { type: String, default: "" },

    // Routific integration storage (ETAs/status)
    routific: {
      pushedAt: { type: Date, default: null },
      orderUuid: { type: String, default: "" },
      lastSyncAt: { type: Date, default: null },
      routeUuid: { type: String, default: "" },
      plannedArrival: { type: Date, default: null },
      plannedDeparture: { type: Date, default: null },
      actualArrival: { type: Date, default: null },
      actualDeparture: { type: Date, default: null },
      stopStatus: { type: String, default: "" },
      driverName: { type: String, default: "" },
    },

    status: {
      state: { type: String, enum: AllowedStates, default: "submitted" },
      note: { type: String, default: "" },
      updatedAt: { type: Date, default: Date.now },
      updatedBy: { type: String, default: "system" },
    },

    statusHistory: {
      type: [{ state: { type: String, enum: AllowedStates }, note: String, at: Date, by: String }],
      default: [],
    },
  },
  { timestamps: true }
);

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const RunLocation = mongoose.model("RunLocation", RunLocationSchema);
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
// ROUTIFIC CLIENT
// =========================
function routificAuthHeader() {
  if (!ROUTIFIC_API_TOKEN_RAW) return "";
  return ROUTIFIC_API_TOKEN_RAW.toLowerCase().startsWith("bearer ")
    ? ROUTIFIC_API_TOKEN_RAW
    : "Bearer " + ROUTIFIC_API_TOKEN_RAW;
}

async function routificRequest(path, { method = "GET", body = null } = {}) {
  if (!ROUTIFIC_WORKSPACE_ID) throw new Error("Missing ROUTIFIC_WORKSPACE_ID");
  if (!ROUTIFIC_API_TOKEN_RAW) throw new Error("Missing ROUTIFIC_API_TOKEN");

  const url = ROUTIFIC_BASE + path;
  const headers = {
    accept: "application/json",
    Authorization: routificAuthHeader(),
  };

  let payload = undefined;
  if (body != null) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const r = await fetch(url, { method, headers, body: payload });
  const text = await r.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }

  if (!r.ok) {
    const msg = data?.message || data?.error || (typeof data === "string" ? data : JSON.stringify(data));
    throw new Error(`Routific ${method} ${path} failed (${r.status}): ${msg}`);
  }
  return data;
}

// Create orders endpoint uses workspaceId as query param 7
async function routificCreateOrders(orderPayloads) {
  const qs = `?workspaceId=${encodeURIComponent(ROUTIFIC_WORKSPACE_ID)}`;
  return routificRequest(`/orders${qs}`, { method: "POST", body: orderPayloads });
}

// Fetch routes endpoint 8
async function routificFetchRoutes(dateYYYYMMDD) {
  const qs = `?workspaceId=${encodeURIComponent(ROUTIFIC_WORKSPACE_ID)}&date=${encodeURIComponent(dateYYYYMMDD)}`;
  return routificRequest(`/routes${qs}`, { method: "GET" });
}

// Fetch route timeline endpoint 9
async function routificFetchTimeline(routeUuid) {
  return routificRequest(`/routes/${encodeURIComponent(routeUuid)}/timeline`, { method: "GET" });
}

// =========================
// PUBLIC CONFIG (Mapbox token)
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

      const rl = await RunLocation.findOne({ runKey: run.runKey }).lean();
      const trackingEnabled = !!rl?.enabled;

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
        trackingEnabled,
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
      trackingEnabled: false,
      trackingEnabledAt: null,
      trackingEnabledBy: "",
      routific: { pushedAt: null, orderUuid: "", lastSyncAt: null, routeUuid: "", plannedArrival: null, plannedDeparture: null, actualArrival: null, actualDeparture: null, stopStatus: "", driverName: "" },
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
        routific: {
          plannedArrivalLocal: order.routific?.plannedArrival ? fmtLocal(order.routific.plannedArrival) : "",
          driverName: order.routific?.driverName || "",
        },
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

// Policy 2 map endpoint (customer)
app.get("/api/orders/:orderId/location", async (req, res) => {
  try{
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok:false, error:"Order not found" });

    const st = order.status?.state || "submitted";
    if (st === "cancelled" || st === "delivered") return res.json({ ok:true, visible:false });

    const rl = await RunLocation.findOne({ runKey: order.runKey }).lean();
    if (!rl || !rl.enabled || rl.lat == null || rl.lng == null) return res.json({ ok:true, visible:false });

    const mode = order.trackingEnabled ? "delivery" : "run";
    res.json({
      ok:true,
      visible:true,
      mode,
      lat: rl.lat,
      lng: rl.lng,
      updatedAtLocal: rl.updatedAt ? fmtLocal(rl.updatedAt) : "",
    });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
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
// MEMBER API
// =========================
app.get("/api/member/orders", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim();
    const items = await Order.find({ "customer.email": email }).sort({ createdAt: -1 }).limit(50).lean();

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
        routific: {
          plannedArrivalLocal: o.routific?.plannedArrival ? fmtLocal(o.routific.plannedArrival) : "",
          driverName: o.routific?.driverName || "",
          stopStatus: o.routific?.stopStatus || "",
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
// ADMIN: RUN TRACKING + LOCATION
// =========================
async function ensureRunLocation(runKey){
  const rl = await RunLocation.findOne({ runKey });
  if (rl) return rl;
  return await RunLocation.create({ runKey, enabled:false });
}

app.get("/api/admin/runs/active", requireLogin, requireAdmin, async (_req, res) => {
  try{
    const runs = await ensureUpcomingRuns();
    const out = {};
    for (const type of ["local","owen"]){
      const run = runs[type];
      const rl = await RunLocation.findOne({ runKey: run.runKey }).lean();
      out[type] = {
        runKey: run.runKey,
        type: run.type,
        enabled: !!rl?.enabled,
        updatedAtLocal: rl?.updatedAt ? fmtLocal(rl.updatedAt) : "",
      };
    }
    res.json({ ok:true, runs: out });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
  }
});

app.post("/api/admin/runs/:runKey/tracking", requireLogin, requireAdmin, async (req, res) => {
  try{
    const runKey = String(req.params.runKey || "").trim();
    const enabled = yn(req.body?.enabled);
    const by = String(req.user?.email || "admin").toLowerCase();

    const rl = await ensureRunLocation(runKey);
    rl.enabled = enabled;
    rl.enabledAt = enabled ? new Date() : rl.enabledAt;
    rl.enabledBy = enabled ? by : rl.enabledBy;
    await rl.save();
    res.json({ ok:true, enabled: rl.enabled });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
  }
});

app.post("/api/admin/runs/:runKey/location", requireLogin, requireAdmin, async (req, res) => {
  try{
    const runKey = String(req.params.runKey || "").trim();
    const { lat, lng, accuracy, heading, speed } = req.body || {};
    const rl = await ensureRunLocation(runKey);
    if (!rl.enabled) return res.status(403).json({ ok:false, error:"Run tracking is OFF" });

    const la = Number(lat), ln = Number(lng);
    if (!Number.isFinite(la) || !Number.isFinite(ln)) return res.status(400).json({ ok:false, error:"Invalid lat/lng" });

    rl.lat = la;
    rl.lng = ln;
    rl.accuracy = Number.isFinite(Number(accuracy)) ? Number(accuracy) : rl.accuracy;
    rl.heading = Number.isFinite(Number(heading)) ? Number(heading) : rl.heading;
    rl.speed = Number.isFinite(Number(speed)) ? Number(speed) : rl.speed;
    rl.updatedAt = new Date();
    await rl.save();
    res.json({ ok:true });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
  }
});

// =========================
// ADMIN API: ORDERS + ROUTIFIC
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

    if (state === "packed"){
      order.trackingEnabled = true;
      order.trackingEnabledAt = new Date();
      order.trackingEnabledBy = by;
      order.statusHistory.push({ state, note: "Tracking enabled (Packed)", at: new Date(), by });
    }
    if (state === "cancelled" || state === "delivered"){
      order.trackingEnabled = false;
    }

    await order.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post("/api/admin/orders/:orderId/tracking", requireLogin, requireAdmin, async (req, res) => {
  try{
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const enabled = yn(req.body?.enabled);
    const by = String(req.user?.email || "admin").toLowerCase();

    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok:false, error:"Order not found" });

    order.trackingEnabled = enabled;
    order.trackingEnabledAt = enabled ? new Date() : order.trackingEnabledAt;
    order.trackingEnabledBy = enabled ? by : order.trackingEnabledBy;
    order.statusHistory.push({ state: order.status?.state || "submitted", note: `Tracking override: ${enabled ? "ON" : "OFF"}`, at: new Date(), by });

    await order.save();
    res.json({ ok:true, trackingEnabled: order.trackingEnabled });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
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
    order.trackingEnabled = false;
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
    const kind = String(req.body?.kind || "").trim();
    const status = String(req.body?.status || "").trim();
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

// Routific: push run orders
app.post("/api/admin/routific/push-run", requireLogin, requireAdmin, async (req, res) => {
  try{
    const runKey = String(req.body?.runKey || "").trim();
    if (!runKey) return res.status(400).json({ ok:false, error:"Missing runKey" });
    if (!ROUTIFIC_WORKSPACE_ID || !ROUTIFIC_API_TOKEN_RAW) {
      return res.status(500).json({ ok:false, error:"Routific env not configured (ROUTIFIC_WORKSPACE_ID/ROUTIFIC_API_TOKEN)" });
    }

    const orders = await Order.find({
      runKey,
      "status.state": { $in: Array.from(ACTIVE_STATES) },
    }).sort({ createdAt: 1 });

    if (!orders.length) return res.json({ ok:true, pushed:0, message:"No active orders to push for this runKey." });

    // Build Routific order payloads.
    // We put your TGR orderId into customerOrderNumber so we can reconcile on sync. 10
    const payload = orders.map(o => {
      const name = o.customer?.fullName || o.customer?.email || o.orderId;
      const phone = o.customer?.phone || "";
      const email = o.customer?.email || "";

      const addr = `${o.address?.streetAddress || ""}, ${o.address?.town || ""}, Ontario, Canada`;
      const instructions = [
        `TGR Order: ${o.orderId}`,
        `Zone: ${o.address?.zone || ""}`,
        `Primary store: ${o.stores?.primary || ""}`,
        (o.stores?.extra || []).length ? `Extra stores: ${(o.stores.extra || []).join(", ")}` : "",
        o.preferences?.dropoffPref ? `Drop-off: ${o.preferences.dropoffPref}` : "",
        o.preferences?.subsPref ? `Subs: ${o.preferences.subsPref}` : "",
      ].filter(Boolean).join(" | ");

      // duration at stop: default 6 minutes (tweak later)
      const durationSec = 6 * 60;

      return {
        name,
        phone,
        email,
        customerOrderNumber: o.orderId,
        instructions,
        duration: durationSec,
        locations: [{ address: addr }],
      };
    });

    const resp = await routificCreateOrders(payload); // POST /orders?workspaceId=... 11

    // Response structure can vary by version; we defensively map by customerOrderNumber when possible.
    const now = new Date();
    const updated = [];

    // Best-effort: If resp returns an array of created orders, match by customerOrderNumber.
    const created = Array.isArray(resp) ? resp : (resp.orders || resp.data || resp.result || []);
    const createdByOrderNumber = new Map();
    if (Array.isArray(created)) {
      for (const it of created) {
        const on = String(it.customerOrderNumber || it.customer_order_number || it.orderNumber || it.order_number || "").trim();
        const uuid = String(it.uuid || it.id || it.orderUuid || it.order_uuid || "").trim();
        if (on && uuid) createdByOrderNumber.set(on, uuid);
      }
    }

    for (const o of orders) {
      const uuid = createdByOrderNumber.get(o.orderId) || "";
      await Order.updateOne(
        { _id: o._id },
        {
          $set: {
            "routific.pushedAt": now,
            "routific.orderUuid": uuid || o.routific?.orderUuid || "",
          },
        }
      );
      updated.push({ orderId: o.orderId, routificOrderUuid: uuid || "" });
    }

    res.json({ ok:true, pushed: orders.length, items: updated, raw: resp });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
  }
});

// Routific: sync routes+timeline for a date, write planned ETAs into orders
app.post("/api/admin/routific/sync-day", requireLogin, requireAdmin, async (req, res) => {
  try{
    if (!ROUTIFIC_WORKSPACE_ID || !ROUTIFIC_API_TOKEN_RAW) {
      return res.status(500).json({ ok:false, error:"Routific env not configured (ROUTIFIC_WORKSPACE_ID/ROUTIFIC_API_TOKEN)" });
    }

    const date = String(req.body?.date || "").trim(); // YYYY-MM-DD
    const dateYYYYMMDD = date || nowTz().format("YYYY-MM-DD");

    const routesResp = await routificFetchRoutes(dateYYYYMMDD); // GET /routes?... 12
    const routes = routesResp?.routes || routesResp?.data || routesResp || [];
    const list = Array.isArray(routes) ? routes : (routes.routes || []);

    let updatedCount = 0;
    const updates = [];

    for (const r of list) {
      const routeUuid = String(r.uuid || r.routeUuid || r.id || "").trim();
      const driverName = String(r.driverName || r.driver_name || r.name || "").trim();
      if (!routeUuid) continue;

      const tl = await routificFetchTimeline(routeUuid); // GET /routes/{uuid}/timeline 13
      const stops = tl?.stops || tl?.timeline || tl?.data || [];

      // Each stop may contain orders. We'll try to find TGR orderId via customerOrderNumber if present.
      for (const stop of (Array.isArray(stops) ? stops : [])) {
        const plannedArrival = stop.plannedArrivalTime || stop.planned_arrival_time || stop.plannedArrival || null;
        const plannedDeparture = stop.plannedDepartureTime || stop.planned_departure_time || stop.plannedDeparture || null;
        const actualArrival = stop.actualArrivalTime || stop.actual_arrival_time || stop.actualArrival || null;
        const actualDeparture = stop.actualDepartureTime || stop.actual_departure_time || stop.actualDeparture || null;
        const stopStatus = stop.status || stop.stopStatus || "";

        const orders = stop.orders || stop.orderUuids || stop.orderUUIDs || [];
        // If orders are objects, check customerOrderNumber on them.
        for (const od of (Array.isArray(orders) ? orders : [])) {
          let tgrOrderId = "";
          let routificOrderUuid = "";

          if (typeof od === "string") {
            routificOrderUuid = od;
          } else if (od && typeof od === "object") {
            tgrOrderId = String(od.customerOrderNumber || od.customer_order_number || od.orderNumber || "").trim().toUpperCase();
            routificOrderUuid = String(od.uuid || od.id || od.orderUuid || "").trim();
          }

          let query = null;
          if (tgrOrderId) query = { orderId: tgrOrderId };
          else if (routificOrderUuid) query = { "routific.orderUuid": routificOrderUuid };

          if (!query) continue;

          const set = {
            "routific.lastSyncAt": new Date(),
            "routific.routeUuid": routeUuid,
            "routific.driverName": driverName,
            "routific.stopStatus": stopStatus,
          };

          if (plannedArrival) set["routific.plannedArrival"] = new Date(plannedArrival);
          if (plannedDeparture) set["routific.plannedDeparture"] = new Date(plannedDeparture);
          if (actualArrival) set["routific.actualArrival"] = new Date(actualArrival);
          if (actualDeparture) set["routific.actualDeparture"] = new Date(actualDeparture);

          const wr = await Order.updateOne(query, { $set: set });
          if (wr?.modifiedCount) {
            updatedCount += wr.modifiedCount;
            updates.push({ order: tgrOrderId || routificOrderUuid, routeUuid, driverName, plannedArrival });
          }
        }
      }
    }

    res.json({ ok:true, date: dateYYYYMMDD, updatedCount, updates });
  } catch(e){
    res.status(500).json({ ok:false, error:String(e) });
  }
});

// =========================
// MEMBER PORTAL (UPGRADED + MAP + ETA)
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
<link href="https://api.mapbox.com/mapbox-gl-js/v3.6.0/mapbox-gl.css" rel="stylesheet">
<script src="https://api.mapbox.com/mapbox-gl-js/v3.6.0/mapbox-gl.js"></script>
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
  .mapBox{ border: 1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.22); border-radius: 16px; overflow:hidden; margin-top:10px; }
  #mMap{ width:100%; height:240px; }
  @media(max-width:820px){ .btn{ width:100%; } }
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
          <a class="btn primary" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=membership">Buy / Change Plan</a>
          <button class="btn secondary" id="btnCancelMembership" type="button">Cancel membership</button>
        </div>

        <div class="hr"></div>

        <div class="row">
          <a class="btn ghost" href="${escapeHtml(SQUARE_LINK_STANDARD)}" target="_blank" rel="noopener">Standard</a>
          <a class="btn ghost" href="${escapeHtml(SQUARE_LINK_ROUTE)}" target="_blank" rel="noopener">Route</a>
          <a class="btn ghost" href="${escapeHtml(SQUARE_LINK_ACCESS)}" target="_blank" rel="noopener">Access</a>
          <a class="btn ghost" href="${escapeHtml(SQUARE_LINK_ACCESSPRO)}" target="_blank" rel="noopener">Access Pro</a>
        </div>
      </div>

      <div class="col card" style="background:rgba(0,0,0,.20); box-shadow:none;">
        <h2>Payments</h2>
        <div class="muted">Paste your Order ID in the Square note.</div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn primary" href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}" target="_blank" rel="noopener">Pay Grocery Total</a>
          <a class="btn secondary" href="${escapeHtml(SQUARE_PAY_FEES_LINK)}" target="_blank" rel="noopener">Pay Service & Delivery Fees</a>
        </div>
      </div>
    </div>

    <div class="hr"></div>

    <div class="card" style="background:rgba(0,0,0,.20); box-shadow:none;">
      <h2>Active orders</h2>
      <div class="muted">Map appears when run tracking is active. Planned ETA appears after Routific sync.</div>
      <div class="hr"></div>
      <div id="activeWrap" class="muted">Loading…</div>

      <div id="mapBlock" style="display:none;">
        <div class="hr"></div>
        <div style="font-weight:1000;font-size:18px;">Live Map</div>
        <div class="muted" id="mMapHint" style="margin-top:6px;"></div>
        <div class="mapBox"><div id="mMap"></div></div>
        <div class="muted" id="mMapUpdated" style="margin-top:8px;"></div>
      </div>
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
              <th>ETA</th>
              <th>Fees</th>
              <th>Payments</th>
            </tr>
          </thead>
          <tbody id="histRows"></tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<script>
  const API_ME = "/api/me";
  const API_MEMBER_ORDERS = "/api/member/orders";
  const API_CANCEL_TOKEN = (id) => "/api/member/orders/" + encodeURIComponent(id) + "/cancel-token";
  const API_CANCEL = (id) => "/api/orders/" + encodeURIComponent(id) + "/cancel";
  const API_CANCEL_MEMBERSHIP = "/api/member/membership/cancel";
  const API_CONFIG = "/api/public/config";
  const API_LOC = (id) => "/api/orders/" + encodeURIComponent(id) + "/location";

  let mapboxToken = "";
  let mMap = null;
  let mMarker = null;
  let pollTimer = null;
  let currentActiveOrderId = "";

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

  async function loadConfig(){
    if (mapboxToken) return;
    const r = await fetch(API_CONFIG, { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if (r.ok && d.ok) mapboxToken = d.mapboxPublicToken || "";
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

  function ensureMemberMap(center){
    if (!mapboxToken) return false;
    if (mMap) return true;
    mapboxgl.accessToken = mapboxToken;
    mMap = new mapboxgl.Map({
      container: "mMap",
      style: "mapbox://styles/mapbox/streets-v12",
      center: center || [-81.66, 45.25],
      zoom: 11,
    });
    mMap.addControl(new mapboxgl.NavigationControl({ showCompass:false }), "top-right");
    return true;
  }

  function setMemberMarker(lng, lat){
    if (!mMap) return;
    if (!mMarker){
      mMarker = new mapboxgl.Marker({ color:"#e3342f" }).setLngLat([lng,lat]).addTo(mMap);
    } else {
      mMarker.setLngLat([lng,lat]);
    }
  }

  async function pollLocation(){
    if (!currentActiveOrderId) return;
    await loadConfig();
    if (!mapboxToken) return;

    const r = await fetch(API_LOC(currentActiveOrderId), { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) return;

    const block = document.getElementById("mapBlock");
    if (!d.visible){
      block.style.display = "none";
      return;
    }

    block.style.display = "";
    document.getElementById("mMapHint").textContent =
      d.mode === "delivery" ? "Delivery tracking is ON for your order (Packed)." : "Run tracking is ON (heading to store / shopping).";
    document.getElementById("mMapUpdated").textContent = d.updatedAtLocal ? ("Last update: " + d.updatedAtLocal) : "";

    const ok = ensureMemberMap([d.lng, d.lat]);
    if (!ok) return;
    setMemberMarker(d.lng, d.lat);
  }

  async function loadOrders(){
    const r = await fetch(API_MEMBER_ORDERS, { credentials:"include" });
    const data = await r.json().catch(()=>({}));
    if(!r.ok || data.ok === false) throw new Error(data.error || "Orders failed");

    const active = data.active || [];
    const history = data.history || [];

    currentActiveOrderId = active.length ? active[0].orderId : "";
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;

    const aw = document.getElementById("activeWrap");
    if(!active.length){
      aw.innerHTML = "<span class='muted'>No active orders right now.</span>";
      document.getElementById("mapBlock").style.display = "none";
    } else {
      aw.innerHTML = active.map(o => {
        const fees = o.pricingSnapshot?.totalFees ?? 0;
        const payFees = o.payments?.fees?.status || "unpaid";
        const payGro = o.payments?.groceries?.status || "unpaid";
        const st = o.status?.state || "submitted";
        const note = o.status?.note || "";
        const eta = (o.routific && o.routific.plannedArrivalLocal) ? o.routific.plannedArrivalLocal : "—";
        const driver = (o.routific && o.routific.driverName) ? o.routific.driverName : "";

        return \`
          <div class="card" style="background:rgba(0,0,0,.18); box-shadow:none; margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;">
              <div>
                <div style="font-weight:1000;font-size:18px;">\${o.orderId} <span class="pill">\${st}</span></div>
                <div class="muted">\${o.runType} • \${o.runKey} • \${o.createdAtLocal}</div>
                <div class="muted">\${o.town} (\${o.zone}) • \${o.streetAddress}</div>
                <div class="muted">Planned ETA: <strong>\${eta}</strong>\${driver ? (" • Driver: <strong>"+driver+"</strong>") : ""}</div>
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
            const tr = await fetch(API_CANCEL_TOKEN(orderId), { method:"POST", credentials:"include" });
            const td = await tr.json().catch(()=>({}));
            if(!tr.ok || td.ok === false) throw new Error(td.error || "Could not mint cancel token");
            const token = td.cancelToken;

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

      await pollLocation();
      pollTimer = setInterval(pollLocation, 12000);
    }

    const tb = document.getElementById("histRows");
    tb.innerHTML = history.map(o => {
      const fees = o.pricingSnapshot?.totalFees ?? 0;
      const payFees = o.payments?.fees?.status || "unpaid";
      const payGro = o.payments?.groceries?.status || "unpaid";
      const st = o.status?.state || "submitted";
      const eta = (o.routific && o.routific.plannedArrivalLocal) ? o.routific.plannedArrivalLocal : "—";
      return \`
        <tr>
          <td style="font-weight:1000;">\${o.orderId}</td>
          <td class="muted">\${o.createdAtLocal}</td>
          <td><span class="pill">\${o.runType}</span><div class="muted" style="margin-top:4px;">\${o.runKey}</div></td>
          <td><span class="pill">\${st}</span><div class="muted" style="margin-top:4px;">\${o.status?.note || ""}</div></td>
          <td class="muted">\${eta}</td>
          <td>\${money(fees)}</td>
          <td class="muted">Fees: <strong>\${payFees}</strong><br>Groceries: <strong>\${payGro}</strong></td>
        </tr>
      \`;
    }).join("");

    if(!history.length){
      tb.innerHTML = "<tr><td colspan='7' class='muted'>No previous orders yet.</td></tr>";
    }
  }

  document.getElementById("btnCancelMembership").addEventListener("click", async ()=>{
    const ok = confirm("Cancel your membership status in TGR? (Square billing may still need cancellation if enabled later.)");
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
      setInterval(loadOrders, 30000);
    } catch(e){
      toast("Portal error: " + String(e.message || e));
    }
  })();
</script>

</body>
</html>`);
});

// =========================
// ADMIN PAGE (adds Routific controls)
// =========================
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
      text-decoration:none;
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
    .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
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
          <a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a>
          <a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a>
        </div>
      </div>

      <div class="toast" id="toast"></div>

      <div class="grid" style="margin-top:12px;">
        <div class="card" style="background:rgba(0,0,0,.22);">
          <div style="font-weight:1000;">Run tracking (Start/Stop)</div>
          <div class="muted">Broadcast your live location for the active run. Customers see the dot while ON.</div>
          <div class="row" style="margin-top:10px;">
            <button class="btn primary" id="startLocal">Start Local Run Tracking</button>
            <button class="btn" id="stopLocal">Stop Local</button>
          </div>
          <div class="row" style="margin-top:10px;">
            <button class="btn primary" id="startOwen">Start Owen Run Tracking</button>
            <button class="btn" id="stopOwen">Stop Owen</button>
          </div>
          <div class="muted" id="trkInfo" style="margin-top:10px;">Loading run keys…</div>
          <div class="muted" id="trkLast" style="margin-top:6px;"></div>

          <div class="hr"></div>

          <div style="font-weight:1000;">Routific (Routes + ETAs)</div>
          <div class="muted">Push orders to Routific and sync planned ETAs back.</div>
          <div class="row" style="margin-top:10px;">
            <button class="btn primary" id="pushLocal">Push Local Run → Routific</button>
            <button class="btn primary" id="pushOwen">Push Owen Run → Routific</button>
          </div>
          <div class="row" style="margin-top:10px;">
            <input id="syncDate" placeholder="YYYY-MM-DD (blank = today)" />
            <button class="btn" id="syncDay">Sync ETAs from Routific</button>
          </div>
          <div class="muted" id="routificInfo" style="margin-top:10px;">Routific: not synced yet.</div>
        </div>

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
          <div class="muted" style="margin-top:8px;">Tip: clicking Packed enables delivery-mode tracking for that order.</div>
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

            <div class="hr"></div>

            <div style="font-weight:900;">Tracking override (order)</div>
            <div class="muted">For this order only. Packed normally turns ON automatically.</div>
            <div class="actions" style="margin-top:10px;">
              <button class="btn small" id="trkOn">Tracking ON</button>
              <button class="btn small" id="trkOff">Tracking OFF</button>
            </div>

            <div class="hr"></div>

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

        <div class="card" style="background:rgba(0,0,0,.22);">
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
                  <th>ETA</th>
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
  </div>

<script>
  const api = {
    list: "/api/admin/orders",
    setStatus: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/status",
    cancel: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/cancel",
    del: (id) => "/api/admin/orders/" + encodeURIComponent(id),
    pay: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/payments",
    trkOrder: (id) => "/api/admin/orders/" + encodeURIComponent(id) + "/tracking",
    runs: "/api/admin/runs/active",
    trkRun: (runKey) => "/api/admin/runs/" + encodeURIComponent(runKey) + "/tracking",
    locRun: (runKey) => "/api/admin/runs/" + encodeURIComponent(runKey) + "/location",
    pushRun: "/api/admin/routific/push-run",
    syncDay: "/api/admin/routific/sync-day",
  };

  let selected = null;
  let runKeys = { local:"", owen:"" };
  let watchId = null;
  let activeRunKey = "";

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

  async function fetchRuns(){
    const r = await fetch(api.runs, { credentials:"include" });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Runs failed");
    runKeys.local = d.runs?.local?.runKey || "";
    runKeys.owen = d.runs?.owen?.runKey || "";
    const lOn = d.runs?.local?.enabled ? "ON" : "OFF";
    const oOn = d.runs?.owen?.enabled ? "ON" : "OFF";
    document.getElementById("trkInfo").textContent = "Local: " + runKeys.local + " (" + lOn + ") • Owen: " + runKeys.owen + " (" + oOn + ")";
  }

  async function setRunTracking(runKey, enabled){
    const r = await fetch(api.trkRun(runKey), {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ enabled: enabled ? "yes" : "no" }),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Run tracking update failed");
  }

  async function postLocation(runKey, pos){
    const c = pos.coords || {};
    const payload = {
      lat: c.latitude,
      lng: c.longitude,
      accuracy: c.accuracy,
      heading: c.heading,
      speed: c.speed,
    };
    const r = await fetch(api.locRun(runKey), {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify(payload),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Location post failed");
    document.getElementById("trkLast").textContent = "Last sent: " + new Date().toLocaleTimeString();
  }

  async function startBroadcast(runKey){
    if (!runKey) return toast("Run key missing.");
    if (!navigator.geolocation) return toast("Geolocation not supported on this device/browser.");
    if (watchId != null) { navigator.geolocation.clearWatch(watchId); watchId = null; }

    await setRunTracking(runKey, true);
    activeRunKey = runKey;

    toast("Tracking started ✅ " + runKey);

    watchId = navigator.geolocation.watchPosition(
      (pos) => { postLocation(activeRunKey, pos).catch(e=>toast(String(e.message||e))); },
      (err) => { toast("GPS error: " + (err.message || err)); },
      { enableHighAccuracy:true, maximumAge: 2000, timeout: 15000 }
    );

    await fetchRuns();
  }

  async function stopBroadcast(runKey){
    if (!runKey) return toast("Run key missing.");
    if (watchId != null) { navigator.geolocation.clearWatch(watchId); watchId = null; }
    activeRunKey = "";
    await setRunTracking(runKey, false);
    toast("Tracking stopped.");
    await fetchRuns();
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
      const eta = o.routific?.plannedArrival ? new Date(o.routific.plannedArrival).toLocaleString() : "";

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
        <td class="muted" style="font-size:12px;">\${eta || "—"}</td>
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

  async function setOrderTracking(enabled){
    if (!selected) return toast("Select an order first.");
    const r = await fetch(api.trkOrder(selected.orderId), {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ enabled: enabled ? "yes" : "no" }),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Tracking toggle failed");
    toast("Tracking " + (enabled ? "ON" : "OFF") + " for " + selected.orderId);
    await fetchOrders();
  }

  async function routificPush(runKey){
    const r = await fetch(api.pushRun, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ runKey }),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Push failed");
    document.getElementById("routificInfo").textContent = "Pushed " + d.pushed + " order(s) for " + runKey + ".";
    toast("Routific push ✅");
    await fetchOrders();
  }

  async function routificSync(date){
    const r = await fetch(api.syncDay, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"include",
      body: JSON.stringify({ date }),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || d.ok === false) throw new Error(d.error || "Sync failed");
    document.getElementById("routificInfo").textContent =
      "Synced " + d.updatedCount + " ETA update(s) for " + d.date + ".";
    toast("Routific sync ✅");
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

  document.getElementById("trkOn").addEventListener("click", ()=> setOrderTracking(true).catch(e=>toast(String(e.message||e))));
  document.getElementById("trkOff").addEventListener("click", ()=> setOrderTracking(false).catch(e=>toast(String(e.message||e))));

  document.getElementById("startLocal").addEventListener("click", ()=> startBroadcast(runKeys.local).catch(e=>toast(String(e.message||e))));
  document.getElementById("stopLocal").addEventListener("click", ()=> stopBroadcast(runKeys.local).catch(e=>toast(String(e.message||e))));
  document.getElementById("startOwen").addEventListener("click", ()=> startBroadcast(runKeys.owen).catch(e=>toast(String(e.message||e))));
  document.getElementById("stopOwen").addEventListener("click", ()=> stopBroadcast(runKeys.owen).catch(e=>toast(String(e.message||e))));

  document.getElementById("pushLocal").addEventListener("click", ()=> routificPush(runKeys.local).catch(e=>toast(String(e.message||e))));
  document.getElementById("pushOwen").addEventListener("click", ()=> routificPush(runKeys.owen).catch(e=>toast(String(e.message||e))));
  document.getElementById("syncDay").addEventListener("click", ()=>{
    const date = document.getElementById("syncDate").value.trim();
    routificSync(date).catch(e=>toast(String(e.message||e)));
  });

  fetchRuns().then(fetchOrders).catch(e=>toast(String(e.message||e)));
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