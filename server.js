/**
 * server.js — Tobermory Grocery Run backend (Express + MongoDB)
 * READY TO SELL MEMBERSHIPS + TAKE PAYMENTS TODAY
 *
 * What this supports:
 *  - Membership subscriptions via Square subscription-enabled Payment Links:
 *      POST /api/memberships/checkout   { tier: "standard"|"route"|"access"|"accesspro" }
 *  - One-time payments via Square Payment Links:
 *      POST /api/payments/checkout     { kind: "groceries"|"fees" }
 *  - Runs (live slot counter + cutoffs) + Orders (multipart form w/ optional file upload)
 *
 * REQUIRED Render ENV:
 *  - SESSION_SECRET
 *  - MONGO_URI  (or MONGODB_URI)
 *  - SQUARE_LINK_STANDARD
 *  - SQUARE_LINK_ROUTE
 *  - SQUARE_LINK_ACCESS
 *  - SQUARE_LINK_ACCESSPRO
 *  - SQUARE_PAY_GROCERIES_LINK
 *  - SQUARE_PAY_FEES_LINK
 *
 * OPTIONAL:
 *  - TZ  (defaults America/Toronto)
 */

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");

// connect-mongo CJS/ESM interop (fixes MongoStore.create is not a function on some installs)
const MongoStorePkg = require("connect-mongo");
const MongoStore = MongoStorePkg.default || MongoStorePkg;

const cors = require("cors");

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

// Cookies across subdomains:
// Start with LAX. If your frontend fetch() to api subdomain doesn't send cookies, switch to:
//   COOKIE_SAMESITE="none" AND COOKIE_DOMAIN=".tobermorygroceryrun.ca"
const COOKIE_SAMESITE = "lax";
const COOKIE_DOMAIN = undefined;

// Lock origins in production
const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
];

// Square subscription payment links (set in Render env)
const SQUARE_LINKS = {
  standard: process.env.SQUARE_LINK_STANDARD,
  route: process.env.SQUARE_LINK_ROUTE,
  access: process.env.SQUARE_LINK_ACCESS,
  accesspro: process.env.SQUARE_LINK_ACCESSPRO,
};

// Square one-time payment links (set in Render env)
const SQUARE_PAY_LINKS = {
  groceries: process.env.SQUARE_PAY_GROCERIES_LINK, // customer pays grocery total
  fees: process.env.SQUARE_PAY_FEES_LINK, // customer pays service/delivery fees
};

const app = express();

// =========================
// CORS + middleware
// =========================
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true); // allow no-origin requests
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// Render/proxy support
app.set("trust proxy", 1);

// =========================
// Sessions (Mongo-backed)
// =========================
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
      ttl: 60 * 60 * 24 * 14, // 14 days
    }),

    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: COOKIE_SAMESITE,
      ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

// Uploads (local disk)
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
});

// =========================
// Pricing model (server truth)
// =========================
const PRICING = {
  serviceFee: 25,
  zone: { A: 20, B: 15, C: 10, D: 25 },
  owenRunFeePerOrder: 20,
  addOns: {
    extraStore: 8,
    parcelDrop: 10,
    parcelBulkyExtra: 8,
    liquor: 12,
    fastFood: 10,
    waitPerBlock: 10,
    rideSeat: 45,
    rideSeatSouthOfFerndale: 30,
    bulkyPerItem: 18,
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

// Membership estimator rules (server-side approximation; actual billing handled by Square)
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
// Mongo models
// =========================
const CounterSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true },
    seq: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const RunSchema = new mongoose.Schema(
  {
    runKey: { type: String, unique: true },
    type: { type: String, enum: ["local", "owen"], required: true },

    opensAt: { type: Date, required: true },
    cutoffAt: { type: Date, required: true },

    maxSlots: { type: Number, default: 12 },

    // Local: 6 orders OR $200 fees
    // Owen:  6 orders AND $300 fees
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

    addOns: {
      pharmacy: { enabled: Boolean, pharmacyName: String, medicationName: String },
      fastFood: { enabled: Boolean, details: String },
      liquor: { enabled: Boolean, details: String, idName: String, idDob: String, idType: String },
      printing: { enabled: Boolean, details: String, pages: Number },
      parcel: { enabled: Boolean, details: String, bulky: Boolean },
      bulky: { enabled: Boolean, count: Number },
      ride: { enabled: Boolean, details: String, seats: Number, southOfFerndale: Boolean },
      wait: { enabled: Boolean, blocks: Number },
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

const Counter = mongoose.model("Counter", CounterSchema);
const Run = mongoose.model("Run", RunSchema);
const Order = mongoose.model("Order", OrderSchema);

// =========================
// Helpers
// =========================
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
      dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(5, "minute").toDate());

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

function computeFeesFromBody(body) {
  const zone = String(body.zone || "");
  const runType = String(body.runType || "");
  const extraStores = safeJsonArray(body.extraStores);

  const add_fastFood = body.addon_fastFood === "yes";
  const add_liquor = body.addon_liquor === "yes";
  const add_printing = body.addon_printing === "yes";
  const add_parcel = body.addon_parcel === "yes";
  const add_bulky = body.addon_bulky === "yes";
  const add_ride = body.addon_ride === "yes";
  const add_wait = body.addon_wait === "yes";

  const pages = Number(body.printPages || 0);
  const parcelBulky = body.parcelBulky === "yes";
  const bulkyCount = Math.max(0, Number(body.bulkyCount || 0));
  const rideSeats = Math.max(1, Number(body.rideSeats || 1));
  const rideSouth = body.rideSouthOfFerndale === "yes";
  const waitBlocks = Math.max(0, Number(body.waitBlocks || 0));

  const memberTier = String(body.memberTier || "");
  const applyPerk = String(body.applyPerk || "yes") === "yes";
  const disc = membershipDiscounts(memberTier, applyPerk);

  const serviceFee = PRICING.serviceFee;
  const zoneFee = PRICING.zone[zone] || 0;
  const runFee = runType === "owen" ? PRICING.owenRunFeePerOrder : 0;

  let addOnsFees = 0;
  if (extraStores.length) addOnsFees += extraStores.length * PRICING.addOns.extraStore;
  if (add_fastFood) addOnsFees += PRICING.addOns.fastFood;
  if (add_liquor) addOnsFees += PRICING.addOns.liquor;
  if (add_printing) addOnsFees += calcPrinting(pages);
  if (add_parcel) {
    addOnsFees += PRICING.addOns.parcelDrop;
    if (parcelBulky) addOnsFees += PRICING.addOns.parcelBulkyExtra;
  }
  if (add_bulky) addOnsFees += bulkyCount * PRICING.addOns.bulkyPerItem;
  if (add_ride) addOnsFees += rideSeats * (rideSouth ? PRICING.addOns.rideSeatSouthOfFerndale : PRICING.addOns.rideSeat);

  let waitFee = add_wait ? waitBlocks * PRICING.addOns.waitPerBlock : 0;
  if (disc.waitWaived) waitFee = 0;

  const serviceOff = Math.min(serviceFee, disc.serviceOff || 0);
  const optionA = Math.min(zoneFee, disc.zoneOff || 0);
  const optionB = Math.min(addOnsFees + waitFee + runFee, disc.freeAddonUpTo || 0);
  const bestOr = Math.max(optionA, optionB);
  const discount = serviceOff + bestOr;

  let surcharges = 0;
  const grocerySubtotal = Number(body.grocerySubtotal || 0);
  if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) {
    surcharges += PRICING.groceryUnderMin.surcharge;
  }

  const totalFees = Math.max(0, serviceFee + zoneFee + runFee + addOnsFees + waitFee + surcharges - discount);

  return { serviceFee, zoneFee, runFee, addOnsFees: addOnsFees + waitFee, surcharges, discount, totalFees };
}

// =========================
// Health
// =========================
app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// =========================
// MEMBERSHIPS (SELL TODAY)
// =========================
app.post("/api/memberships/checkout", (req, res) => {
  const tier = String(req.body?.tier || "").trim().toLowerCase();

  const allowed = new Set(["standard", "route", "access", "accesspro"]);
  if (!allowed.has(tier)) {
    return res.status(400).json({ ok: false, error: "Invalid tier" });
  }

  const url = SQUARE_LINKS[tier];
  if (!url) {
    return res.status(500).json({
      ok: false,
      error: `Missing Square link for '${tier}'. Set Render env var SQUARE_LINK_${tier.toUpperCase()}.`,
    });
  }

  return res.json({ ok: true, tier, checkoutUrl: url });
});

// =========================
// PAYMENTS (ONE-TIME LINKS)
// =========================
app.post("/api/payments/checkout", (req, res) => {
  const kind = String(req.body?.kind || "").trim().toLowerCase(); // "groceries" | "fees"
  const allowed = new Set(["groceries", "fees"]);
  if (!allowed.has(kind)) {
    return res.status(400).json({ ok: false, error: "Invalid payment kind" });
  }

  const url = SQUARE_PAY_LINKS[kind];
  if (!url) {
    const envKey = kind === "groceries" ? "SQUARE_PAY_GROCERIES_LINK" : "SQUARE_PAY_FEES_LINK";
    return res.status(500).json({ ok: false, error: `Missing Render env var ${envKey}` });
  }

  return res.json({ ok: true, kind, checkoutUrl: url });
});

// =========================
// RUNS (Local + Owen)
// =========================
app.get("/api/runs/active", async (req, res) => {
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
// ORDERS
// =========================
app.post("/api/orders", upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {};

    const required = [
      "fullName",
      "email",
      "phone",
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
      const v = String(b[k] || "").trim();
      if (!v) return res.status(400).json({ ok: false, error: "Missing required field: " + k });
    }

    if (String(b.contactAuth || "") !== "yes") {
      return res.status(400).json({ ok: false, error: "Contact authorization is required." });
    }

    if (
      String(b.consent_terms || "") !== "yes" ||
      String(b.consent_accuracy || "") !== "yes" ||
      String(b.consent_dropoff || "") !== "yes"
    ) {
      return res.status(400).json({ ok: false, error: "All required consents must be accepted." });
    }

    if (b.addon_liquor === "yes" && b.dropoffPref === "leave_at_door") {
      return res.status(400).json({ ok: false, error: "Alcohol cannot be left at the door." });
    }
    if (b.addon_pharmacy === "yes" && b.dropoffPref === "leave_at_door") {
      return res.status(400).json({ ok: false, error: "Prescriptions cannot be left at the door." });
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

    const pricing = computeFeesFromBody(b);
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

    const orderDoc = {
      orderId,
      runKey: run.runKey,
      runType,

      customer: {
        fullName: String(b.fullName || "").trim(),
        email: String(b.email || "").trim().toLowerCase(),
        phone: String(b.phone || "").trim(),
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

      addOns: {
        pharmacy: {
          enabled: b.addon_pharmacy === "yes",
          pharmacyName: String(b.pharmacyName || "").trim(),
          medicationName: String(b.medicationName || "").trim(),
        },
        fastFood: { enabled: b.addon_fastFood === "yes", details: String(b.fastFoodDetails || "").trim() },
        liquor: {
          enabled: b.addon_liquor === "yes",
          details: String(b.liquorDetails || "").trim(),
          idName: String(b.idName || "").trim(),
          idDob: String(b.idDob || ""),
          idType: String(b.idType || ""),
        },
        printing: { enabled: b.addon_printing === "yes", details: String(b.printingDetails || "").trim(), pages: Number(b.printPages || 0) },
        parcel: { enabled: b.addon_parcel === "yes", details: String(b.parcelDetails || "").trim(), bulky: b.parcelBulky === "yes" },
        bulky: { enabled: b.addon_bulky === "yes", count: Number(b.bulkyCount || 0) },
        ride: {
          enabled: b.addon_ride === "yes",
          details: String(b.rideDetails || "").trim(),
          seats: Number(b.rideSeats || 1),
          southOfFerndale: b.rideSouthOfFerndale === "yes",
        },
        wait: { enabled: b.addon_wait === "yes", blocks: Number(b.waitBlocks || 0) },
      },

      consents: { terms: true, accuracy: true, dropoff: true },

      pricingSnapshot: pricing,

      status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" },
    };

    const runUpdate = await Run.findOneAndUpdate(
      { runKey: run.runKey, bookedOrdersCount: { $lt: maxSlots } },
      { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricing.totalFees }, $set: { lastRecalcAt: new Date() } },
      { new: true }
    ).lean();

    if (!runUpdate) return res.status(409).json({ ok: false, error: "This run is full." });

    try {
      await Order.create(orderDoc);
    } catch (e) {
      await Run.updateOne(
        { runKey: run.runKey },
        { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -pricing.totalFees }, $set: { lastRecalcAt: new Date() } }
      );
      throw e;
    }

    res.json({ ok: true, orderId, runKey: run.runKey });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/orders/:orderId", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim();
    if (!orderId) return res.status(400).json({ ok: false, error: "Missing orderId" });

    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const out = {
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
    };

    res.json({ ok: true, order: out });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Root
app.get("/", (req, res) => res.send("TGR backend up"));

// Boot
async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");
  app.listen(PORT, () => console.log("Server running on port", PORT));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});