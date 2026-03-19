
FORCE RENDER PUSH
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

// SQUARE SDK IMPORT (Legacy CommonJS Path)
const { Client, Environment } = require("square/legacy");

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

const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI || "mongodb://127.0.0.1:27017/tgr";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const CANCEL_TOKEN_SECRET = process.env.CANCEL_TOKEN_SECRET || SESSION_SECRET;
const TRACKING_TOKEN_SECRET = process.env.TRACKING_TOKEN_SECRET || SESSION_SECRET;

const SESSION_COOKIE_SECURE = String(process.env.SESSION_COOKIE_SECURE || "").toLowerCase() === "true" ? true : process.env.NODE_ENV === "production";
const TZ = process.env.TZ || "America/Toronto";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "";

const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://tobermorygroceryrun.ca";
const MAPBOX_PUBLIC_TOKEN = process.env.MAPBOX_PUBLIC_TOKEN || "";

// Postmark outbound
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || "";
const POSTMARK_FROM_EMAIL = process.env.POSTMARK_FROM_EMAIL || "orders@tobermorygroceryrun.ca";
const POSTMARK_MESSAGE_STREAM = process.env.POSTMARK_MESSAGE_STREAM || "outbound";
const pmClient = POSTMARK_SERVER_TOKEN ? new postmark.ServerClient(POSTMARK_SERVER_TOKEN) : null;

// Twilio SMS
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || "";
const twilioClient = (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

// SQUARE API CONFIG
// Safely handling the Environment to prevent "undefined" errors
const SQUARE_ENVIRONMENT = String(process.env.SQUARE_ENVIRONMENT || "sandbox").toLowerCase() === "production" ? "production" : "sandbox";
const SQUARE_APP_ID = process.env.SQUARE_APP_ID || "";
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";
const SQUARE_LOCATION_ID = process.env.SQUARE_LOCATION_ID || "";

let squareClient = null;
try {
  if (SQUARE_ACCESS_TOKEN && Client) {
    squareClient = new Client({ accessToken: SQUARE_ACCESS_TOKEN, environment: SQUARE_ENVIRONMENT });
    console.log("Square SDK initialized successfully.");
  } else {
    console.warn("⚠️ Square Client not initialized: Missing Token or Client Constructor.");
  }
} catch (err) {
  console.error("⚠️ Square SDK Initialization Error:", err.message);
}

// Membership purchase links
const SQUARE_LINK_STANDARD = process.env.SQUARE_LINK_STANDARD || "https://square.link/u/iaziCZjG";
const SQUARE_LINK_ROUTE = process.env.SQUARE_LINK_ROUTE || "https://square.link/u/P5ROgqyp";
const SQUARE_LINK_ACCESS = process.env.SQUARE_LINK_ACCESS || "https://square.link/u/lHtHtvqG";
const SQUARE_LINK_ACCESSPRO = process.env.SQUARE_LINK_ACCESSPRO || "https://square.link/u/S0Y5Fysa";

const ALLOWED_ORIGINS = ["https://tobermorygroceryrun.ca", "https://www.tobermorygroceryrun.ca", "http://localhost:3000", "http://localhost:8888"];
const CANADAPOST_KEY = process.env.CANADAPOST_KEY || "mn86-az16-ku32-hj78";

// =========================
// APP + MIDDLEWARE
// =========================
const app = express();
app.use(cors({ origin: function (origin, cb) { if (!origin) return cb(null, true); return cb(null, ALLOWED_ORIGINS.includes(origin)); }, credentials: true }));
app.use(express.json({ limit: "6mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("trust proxy", 1);
app.use(session({ name: "tgr.sid", secret: SESSION_SECRET, resave: false, saveUninitialized: false, rolling: true, proxy: true, store: MongoStore.create({ mongoUrl: MONGODB_URI, ttl: 60 * 60 * 24 * 14 }), cookie: { httpOnly: true, secure: SESSION_COOKIE_SECURE, sameSite: "lax", maxAge: 1000 * 60 * 60 * 24 * 14 } }));
app.get("/favicon.ico", (_req, res) => res.status(204).end());
const upload = multer({ dest: "uploads/", limits: { fileSize: 15 * 1024 * 1024 } });

// =========================
// PASSPORT
// =========================
passport.serializeUser((user, done) => done(null, user._id.toString()));
passport.deserializeUser(async (id, done) => { try { const u = await User.findById(id).lean(); done(null, u || null); } catch (e) { done(e); } });

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_CALLBACK_URL) {
  passport.use(new GoogleStrategy({ clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: GOOGLE_CALLBACK_URL }, async (_accessToken, _refreshToken, profile, done) => {
    try {
      const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || ""; const normalized = String(email).toLowerCase().trim(); if (!normalized) return done(null, false);
      const update = { googleId: profile.id, email: normalized, name: profile.displayName || "", photo: (profile.photos && profile.photos[0] && profile.photos[0].value) || "" };
      const u = await User.findOneAndUpdate({ email: normalized }, { $set: update, $setOnInsert: { membershipLevel: "none", membershipStatus: "inactive", renewalDate: null, discounts: [], perks: [], profile: { version: 1, complete: false, defaultId: "", addresses: [] } } }, { upsert: true, new: true });
      return done(null, u);
    } catch (e) { return done(e); }
  }));
}
app.use(passport.initialize());
app.use(passport.session());

// =========================
// PRICING BASELINE
// =========================
const PRICING = {
  serviceFee: 25, zone: { A: 20, B: 15, C: 10, D: 25 }, owenRunFeePerOrder: 20,
  addOns: { extraStore: 8, printingBase: 5, printingFirst10: 1.25, printingAfter10: 0.75, rideLocal: 15, rideOwen: 50 },
  groceryUnderMin: { threshold: 35, surcharge: 19 },
};
const MEMBERSHIP_PLANS = {
  standard: { id: "standard", name: "Standard", monthlyPrice: 15, link: SQUARE_LINK_STANDARD, eligibility: "", perks: ["1 free add-on up to $10 OR $10 off zone fee monthly"] },
  route: { id: "route", name: "Route", monthlyPrice: 25, link: SQUARE_LINK_ROUTE, eligibility: "", perks: ["1 free add-on up to $10 OR $10 off zone fee monthly", "$5 off service fee on 1 order per run day"] },
  access: { id: "access", name: "Access", monthlyPrice: 12, link: SQUARE_LINK_ACCESS, eligibility: "Seniors 60+ or disabled / mobility-limited / low income", perks: ["1 free add-on up to $10 OR $10 off zone fee per run cycle", "$8 off service fee on 1 order per run day", "Free phone/text ordering"] },
  accesspro: { id: "accesspro", name: "Access Pro", monthlyPrice: 20, link: SQUARE_LINK_ACCESSPRO, eligibility: "Enhanced support tier", perks: ["$10 off service fee on 1 order per run day", "1 prescription pickup/delivery included monthly", "Document services included up to 10 pages/month in Tobermory area"] },
};
const MEMBERSHIP_ORDER = ["standard", "route", "access", "accesspro"];
function getPublicMembershipPlans() { return MEMBERSHIP_ORDER.map((id) => { const p = MEMBERSHIP_PLANS[id]; return { id: p.id, name: p.name, monthlyPrice: p.monthlyPrice, priceLabel: `$${p.monthlyPrice} / month`, link: p.link, eligibility: p.eligibility, perks: p.perks }; }); }
function getEffectiveMemberTierForUser(user, requestedTier = "") { const activeTier = user && user.membershipStatus === "active" && user.membershipLevel && user.membershipLevel !== "none" ? String(user.membershipLevel).trim().toLowerCase() : ""; if (activeTier && MEMBERSHIP_PLANS[activeTier]) return activeTier; const reqTier = String(requestedTier || "").trim().toLowerCase(); if (reqTier && MEMBERSHIP_PLANS[reqTier]) return reqTier; return ""; }
function calcPrinting(pages) { const p = Number(pages || 0); if (p <= 0) return 0; const first = Math.min(p, 10); const rest = Math.max(0, p - 10); return PRICING.addOns.printingBase + first * PRICING.addOns.printingFirst10 + rest * PRICING.addOns.printingAfter10; }
function membershipDiscounts(tier, applyPerkYes) { if (!tier || !applyPerkYes) return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false }; if (tier === "standard") return { serviceOff: 0, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false }; if (tier === "route") return { serviceOff: 5, zoneOff: 10, freeAddonUpTo: 10, waitWaived: false }; if (tier === "access") return { serviceOff: 8, zoneOff: 10, freeAddonUpTo: 10, waitWaived: true }; if (tier === "accesspro") return { serviceOff: 10, zoneOff: 0, freeAddonUpTo: 0, waitWaived: true }; return { serviceOff: 0, zoneOff: 0, freeAddonUpTo: 0, waitWaived: false }; }

// =========================
// MODELS
// =========================
const RunSchema = new mongoose.Schema({ runKey: { type: String, unique: true }, type: { type: String, enum: ["local", "owen"], required: true }, opensAt: { type: Date, required: true }, cutoffAt: { type: Date, required: true }, maxSlots: { type: Number, default: 12 }, maxPoints: { type: Number, default: 10 }, minOrders: { type: Number, default: 0 }, minFees: { type: Number, default: 0 }, minLogic: { type: String, enum: ["OR", "AND", "FEES_ONLY"], default: "FEES_ONLY" }, bookedOrdersCount: { type: Number, default: 0 }, bookedPoints: { type: Number, default: 0 }, bookedFeesTotal: { type: Number, default: 0 }, lastRecalcAt: { type: Date } }, { timestamps: true });
const AllowedStates = ["submitted", "confirmed", "shopping", "packed", "out_for_delivery", "delivered", "issue", "cancelled"];
const ACTIVE_STATES = new Set(["submitted", "confirmed", "shopping", "packed", "out_for_delivery"]);

const OrderSchema = new mongoose.Schema(
  {
    orderId: { type: String, unique: true, index: true }, orderClass: { type: String, enum: ["grocery", "ride"], default: "grocery" }, runKey: { type: String, required: true }, runType: { type: String, enum: ["local", "owen"], required: true }, spacePoints: { type: Number, default: 1 }, hold: { type: Boolean, default: false },
    flags: { type: { idRequired: { type: Boolean, default: false }, prescription: { type: Boolean, default: false }, alcohol: { type: Boolean, default: false }, bulky: { type: Boolean, default: false }, newCustomerDepositRequired: { type: Boolean, default: false }, needsContact: { type: Boolean, default: false } }, default: {} },
    customer: { fullName: String, email: String, phone: String, altPhone: { type: String, default: "" }, dob: { type: String, default: "" } }, address: { town: String, streetAddress: String, unit: { type: String, default: "" }, postalCode: { type: String, default: "" }, zone: { type: String, enum: ["A", "B", "C", "D"] } }, stores: { primary: String, extra: [String] }, preferences: { dropoffPref: String, subsPref: String, contactPref: String, contactAuth: Boolean },
    addOns: { prescription: { requested: { type: Boolean, default: false }, pharmacyName: { type: String, default: "" }, notes: { type: String, default: "" } }, liquor: { requested: { type: Boolean, default: false }, storeName: { type: String, default: "" }, notes: { type: String, default: "" }, idRequired: { type: Boolean, default: true } }, printing: { requested: { type: Boolean, default: false }, pages: { type: Number, default: 0 }, notes: { type: String, default: "" } }, fastFood: { requested: { type: Boolean, default: false }, restaurant: { type: String, default: "" }, orderDetails: { type: String, default: "" } }, parcel: { requested: { type: Boolean, default: false }, carrier: { type: String, default: "" }, details: { type: String, default: "" } }, bulky: { requested: { type: Boolean, default: false }, details: { type: String, default: "" } }, ride: { requested: { type: Boolean, default: false }, pickupAddress: { type: String, default: "" }, destination: { type: String, default: "" }, preferredWindow: { type: String, default: "" }, notes: { type: String, default: "" } }, generalNotes: { type: String, default: "" } },
    deliveryMeta: { gateCode: { type: String, default: "" }, buildingAccessNotes: { type: String, default: "" }, parkingNotes: { type: String, default: "" }, budgetCap: { type: Number, default: 0 }, receiptPreference: { type: String, default: "" }, photoProofOk: { type: Boolean, default: false } },
    list: { groceryListText: String, attachment: { originalName: String, mimeType: String, size: Number, path: String } }, consents: { terms: Boolean, accuracy: Boolean, dropoff: Boolean }, pricingSnapshot: { serviceFee: Number, zoneFee: Number, runFee: Number, addOnsFees: Number, surcharges: Number, discount: Number, totalFees: Number },
    payments: { fees: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null } }, groceries: { status: { type: String, default: "unpaid" }, note: { type: String, default: "" }, paidAt: { type: Date, default: null }, squarePaymentId: { type: String, default: "" } } },
    status: { state: { type: String, enum: AllowedStates, default: "submitted" }, note: { type: String, default: "" }, updatedAt: { type: Date, default: Date.now }, updatedBy: { type: String, default: "system" } }, statusHistory: { type: [{ state: { type: String, enum: AllowedStates }, note: String, at: Date, by: String }], default: [] }, adminLog: { type: [{ at: Date, by: String, action: String, meta: Object }], default: [] },
  },
  { timestamps: true }
);

const TrackingSchema = new mongoose.Schema({ runKey: { type: String, unique: true, index: true }, enabled: { type: Boolean, default: false }, startedAt: { type: Date, default: null }, stoppedAt: { type: Date, default: null }, lastLat: { type: Number, default: null }, lastLng: { type: Number, default: null }, lastHeading: { type: Number, default: null }, lastSpeed: { type: Number, default: null }, lastAccuracy: { type: Number, default: null }, lastAt: { type: Date, default: null }, updatedBy: { type: String, default: "system" } }, { timestamps: true });
const CatalogueItemSchema = new mongoose.Schema({ name: { type: String, required: true, unique: true, trim: true }, category: { type: String, default: "General", trim: true }, estimatedPrice: { type: Number, default: 0 }, searchTokens: { type: [String], default: [] } }, { timestamps: true });
CatalogueItemSchema.pre('save', function(next) { if (this.isModified('name') || this.isModified('category')) { const raw = `${this.name} ${this.category}`.toLowerCase().replace(/[^a-z0-9\s]/g, ''); this.searchTokens = Array.from(new Set(raw.split(/\s+/).filter(t => t.length > 1))); } next(); });

const Run = mongoose.model("Run", RunSchema); const Order = mongoose.model("Order", OrderSchema); const Tracking = mongoose.model("Tracking", TrackingSchema); const CatalogueItem = mongoose.model("CatalogueItem", CatalogueItemSchema);

// =========================
// HELPERS
// =========================
function escapeHtml(s) { return String(s || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }
function csvEscape(val) { const s = String(val ?? ""); if (s.includes('"') || s.includes(",") || s.includes("\n") || s.includes("\r")) { return `"${s.replaceAll('"', '""')}"`; } return s; }
function nowTz() { return dayjs().tz(TZ); }
function fmtLocal(d) { return !d ? "" : dayjs(d).tz(TZ).format("ddd MMM D, h:mma"); }
function yn(v) { return v === true || String(v || "").toLowerCase() === "yes"; }
function isProfileComplete(profile) { const p = profile || {}; if (p.complete === true) return true; const fullName = String(p.fullName || "").trim(); const phone = String(p.phone || "").trim(); const contactPref = String(p.contactPref || "").trim(); const contactAuth = p.contactAuth === true; const addresses = Array.isArray(p.addresses) ? p.addresses : []; const hasAddress = addresses.some((a) => !!String(a.streetAddress || "").trim() && !!String(a.town || "").trim() && !!String(a.zone || "").trim() && !!String(a.postalCode || "").trim()); return !!fullName && !!phone && !!contactPref && contactAuth && hasAddress && p.consentTerms === true && p.consentPrivacy === true; }
function requireLogin(req, res, next) { if (!req.user) return res.status(401).json({ ok: false, error: "Sign-in required." }); next(); }
function requireProfileComplete(req, res, next) { if (!isProfileComplete(req.user?.profile || {})) return res.status(403).json({ ok: false, error: "Account setup required. Please complete your profile." }); next(); }
function isAdminEmail(email) { const e = String(email || "").toLowerCase().trim(); return !e ? false : (!ADMIN_EMAILS.length ? true : ADMIN_EMAILS.includes(e)); }
function requireAdmin(req, res, next) { const email = String(req.user?.email || "").toLowerCase().trim(); if (!email || !isAdminEmail(email)) return res.status(403).send("Admin access required."); next(); }
function adminBy(req) { return req.user?.email || "admin"; }

async function pmSend(to, subject, htmlBody, textBody) { try { const rcpt = String(to || "").trim(); if (!pmClient || !POSTMARK_FROM_EMAIL || !rcpt) return; await pmClient.sendEmail({ From: POSTMARK_FROM_EMAIL, To: rcpt, Subject: subject, HtmlBody: htmlBody, TextBody: textBody || "", MessageStream: POSTMARK_MESSAGE_STREAM }); } catch (e) { console.error("Postmark send failed:", String(e)); } }
async function sendSms(toPhone, message) {
  if (!twilioClient || !TWILIO_PHONE_NUMBER || !toPhone) return;
  try {
    let formattedPhone = String(toPhone).replace(/\D/g, "");
    if (formattedPhone.length === 10) formattedPhone = "+1" + formattedPhone;
    else if (formattedPhone.length === 11 && formattedPhone.startsWith("1")) formattedPhone = "+" + formattedPhone;
    await twilioClient.messages.create({ body: message, from: TWILIO_PHONE_NUMBER, to: formattedPhone });
  } catch (error) { console.error("Twilio error:", String(error)); }
}

function money(n) { return Number(n || 0).toFixed(2); }
function base64urlEncode(buf) { return Buffer.from(buf).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function base64urlDecodeToString(b64url) { const pad = b64url.length % 4 ? "=".repeat(4 - (b64url.length % 4)) : ""; const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/") + pad; return Buffer.from(b64, "base64").toString("utf8"); }
function signCancelToken(orderId, expMs) { const payload = `${orderId}.${String(expMs)}`; const sig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payload).digest(); return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`; }
function verifyCancelToken(orderId, token) { try { const parts = String(token || "").trim().split("."); if (parts.length !== 2) return { ok: false }; const payloadStr = base64urlDecodeToString(parts[0]); const [oid, expStr] = payloadStr.split("."); const expMs = Number(expStr); if (oid !== orderId || !Number.isFinite(expMs)) return { ok: false }; const expectedSig = crypto.createHmac("sha256", CANCEL_TOKEN_SECRET).update(payloadStr).digest(); const a = Buffer.from(parts[1], "base64"); const b = Buffer.from(base64urlEncode(expectedSig), "base64"); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false }; return { ok: true, expMs }; } catch { return { ok: false }; } }
function signTrackingToken(orderId, runKey, expMs) { const payload = `${orderId}.${runKey}.${String(expMs)}`; const sig = crypto.createHmac("sha256", TRACKING_TOKEN_SECRET).update(payload).digest(); return `${base64urlEncode(payload)}.${base64urlEncode(sig)}`; }
function verifyTrackingToken(token) { try { const parts = String(token || "").trim().split("."); if (parts.length !== 2) return { ok: false }; const payloadStr = base64urlDecodeToString(parts[0]); const segs = payloadStr.split("."); if (segs.length < 3) return { ok: false }; const orderId = segs[0]; const expStr = segs[segs.length - 1]; const runKey = segs.slice(1, -1).join("."); const expMs = Number(expStr); if (!orderId || !runKey || !Number.isFinite(expMs)) return { ok: false }; const expectedSig = crypto.createHmac("sha256", TRACKING_TOKEN_SECRET).update(payloadStr).digest(); const a = Buffer.from(parts[1], "base64"); const b = Buffer.from(base64urlEncode(expectedSig), "base64"); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false }; if (Date.now() > expMs) return { ok: false, error: "expired" }; return { ok: true, orderId, runKey, expMs }; } catch { return { ok: false }; } }

async function nextOrderId(runType, runKey) {
  const type = String(runType || "").toLowerCase(); const prefix = type === "owen" ? "OWEN" : "LOC"; const datePart = String(runKey || "").slice(0, 10).replaceAll("-", ""); const runDate = /^\d{8}$/.test(datePart) ? datePart : dayjs().tz(TZ).format("YYYYMMDD");
  for (let i = 0; i < 24; i++) { const candidate = `TGR-${prefix}-${runDate}-${String(crypto.randomInt(0, 1000000)).padStart(6, "0")}`; if (!(await Order.exists({ orderId: candidate }))) return candidate; }
  return `TGR-${prefix}-${runDate}-${String(crypto.randomInt(0, 100000000)).padStart(8, "0")}`;
}

function safeJsonArray(str) { try { const v = JSON.parse(str || "[]"); return Array.isArray(v) ? v.map((x) => String(x || "").trim()).filter(Boolean) : []; } catch { return []; } }

function computeFeeBreakdown(input) {
  if (input.orderClass === "ride") { const f = input.runType === "owen" ? PRICING.addOns.rideOwen : PRICING.addOns.rideLocal; return { totals: { serviceFee: 0, zoneFee: 0, runFee: 0, addOnsFees: f, surcharges: 0, discount: 0, totalFees: f } }; }
  const zone = String(input.zone || ""); const runType = String(input.runType || "local"); const extraStores = Array.isArray(input.extraStores) ? input.extraStores.map(String).map((s) => s.trim()).filter(Boolean) : safeJsonArray(input.extraStoresJson); const pages = Math.max(0, Number(input.printPages || 0)); const grocerySubtotal = Math.max(0, Number(input.grocerySubtotal || 0)); const memberTier = String(input.memberTier || ""); const applyPerk = String(input.applyPerk || "yes") === "yes"; const disc = membershipDiscounts(memberTier, applyPerk);
  const serviceFee = PRICING.serviceFee; const zoneFee = PRICING.zone[zone] || 0; const runFee = runType === "owen" ? PRICING.owenRunFeePerOrder : 0;
  let addOnsFees = 0; if (extraStores.length) addOnsFees += extraStores.length * PRICING.addOns.extraStore; if (String(input.addon_printing || "") === "yes" && pages > 0) addOnsFees += calcPrinting(pages);
  let surcharges = 0; if (grocerySubtotal > 0 && grocerySubtotal < PRICING.groceryUnderMin.threshold) surcharges += PRICING.groceryUnderMin.surcharge;
  const discount = Math.min(serviceFee, disc.serviceOff || 0) + Math.max(Math.min(zoneFee, disc.zoneOff || 0), Math.min(addOnsFees + runFee, disc.freeAddonUpTo || 0));
  const totalFees = Math.max(0, serviceFee + zoneFee + runFee + addOnsFees + surcharges - discount);
  return { totals: { serviceFee, zoneFee, runFee, addOnsFees, surcharges, discount, totalFees } };
}

function runKeyToDayjs(runKey) { try { const d = dayjs(String(runKey || "").slice(0, 10)).tz(TZ); return d.isValid() ? d : null; } catch { return null; } }
function nextDow(targetDow, from) { let d = dayjs(from).tz(TZ); let diff = (targetDow - d.day() + 7) % 7; return d.add(diff === 0 ? 7 : diff, "day"); }
function computeTimesForDelivery(deliveryDayjs, type) { const delivery = dayjs(deliveryDayjs).tz(TZ); if (type === "local") return { delivery, cutoff: delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0), opens: delivery.subtract(5, "day").hour(0).minute(0).second(0).millisecond(0) }; return { delivery, cutoff: delivery.subtract(2, "day").hour(18).minute(0).second(0).millisecond(0), opens: delivery.subtract(6, "day").hour(0).minute(0).second(0).millisecond(0) }; }
function runMinimumConfig(type) { if (type === "local") return { minOrders: 0, minFees: 200, minLogic: "FEES_ONLY", minimumText: "Goal: $200 minimum booked fees" }; return { minOrders: 0, minFees: 300, minLogic: "FEES_ONLY", minimumText: "Goal: $300 minimum booked fees" }; }
function meetsMinimums(run) { return run.bookedFeesTotal >= run.minFees; }

async function getOrCreateNextRun(type) {
  const now = nowTz(); let existing = await Run.findOne({ type, cutoffAt: { $gt: now.toDate() } }).sort({ opensAt: 1 }).lean();
  if (existing) { if (now.isBefore(dayjs(existing.cutoffAt).tz(TZ)) && now.isBefore(dayjs(existing.opensAt).tz(TZ))) { const forced = now.subtract(1, "minute").toDate(); await Run.updateOne({ runKey: existing.runKey }, { $set: { opensAt: forced } }); existing.opensAt = forced; } return existing; }
  const latest = await Run.findOne({ type }).sort({ opensAt: -1 }).lean();
  let delivery = latest?.runKey ? (runKeyToDayjs(latest.runKey) || now).add(14, "day") : nextDow(type === "local" ? 6 : 0, now);
  let { cutoff, opens } = computeTimesForDelivery(delivery, type); if (opens.isAfter(now)) opens = now.subtract(1, "minute");
  const cfg = runMinimumConfig(type);
  const created = await Run.create({ runKey: delivery.format("YYYY-MM-DD") + "-" + type, type, opensAt: opens.toDate(), cutoffAt: cutoff.toDate(), maxSlots: 12, maxPoints: 10, minOrders: cfg.minOrders, minFees: cfg.minFees, minLogic: cfg.minLogic });
  return created.toObject();
}

async function ensureUpcomingRuns() {
  const out = {};
  for (const type of ["local", "owen"]) {
    let run = await getOrCreateNextRun(type);
    if (!run.lastRecalcAt || dayjs(run.lastRecalcAt).isBefore(nowTz().subtract(60, "second").toDate())) {
      const agg = await Order.aggregate([{ $match: { runKey: run.runKey, "status.state": { $in: Array.from(ACTIVE_STATES) } } }, { $group: { _id: "$runKey", c: { $sum: 1 }, fees: { $sum: "$pricingSnapshot.totalFees" }, pts: { $sum: "$spacePoints" } } }]);
      const c = agg?.[0]?.c || 0; const fees = agg?.[0]?.fees || 0; const pts = agg?.[0]?.pts || 0;
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
app.get("/api/public/catalogue/search", async (req, res) => { try { const q = String(req.query.q || "").trim().toLowerCase(); if (!q || q.length < 2) return res.json({ ok: true, items: [] }); const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"); res.json({ ok: true, items: await CatalogueItem.find({ $or: [{ name: re }, { category: re }] }).limit(15).lean() }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.get("/api/admin/catalogue", requireLogin, requireAdmin, async (req, res) => { res.json({ ok: true, items: await CatalogueItem.find().sort({ category: 1, name: 1 }).lean() }); });
app.post("/api/admin/catalogue", requireLogin, requireAdmin, async (req, res) => { try { const { name, category, estimatedPrice } = req.body; if (!name) return res.status(400).json({ ok: false, error: "Name is required" }); res.json({ ok: true, item: await CatalogueItem.findOneAndUpdate({ name: String(name).trim() }, { $set: { category: String(category || "General").trim(), estimatedPrice: Number(estimatedPrice || 0) } }, { upsert: true, new: true }) }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.delete("/api/admin/catalogue/:id", requireLogin, requireAdmin, async (req, res) => { await CatalogueItem.findByIdAndDelete(req.params.id); res.json({ ok: true }); });

// =========================
// PUBLIC CONFIG & TRACKING
// =========================
app.get("/api/public/tracking/:runKey", async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim(); const vt = verifyTrackingToken(String(req.query.token || "").trim()); if (!vt.ok || vt.runKey !== runKey) return res.status(403).json({ ok: false, error: "Invalid token." });
    const order = await Order.findOne({ orderId: vt.orderId, runKey }).lean(); if (!order || !ACTIVE_STATES.has(order?.status?.state || "submitted")) return res.status(403).json({ ok: false, error: "Tracking unavailable." });
    const t = await Tracking.findOneAndUpdate({ runKey }, { $setOnInsert: { runKey, enabled: false, updatedBy: "system" } }, { upsert: true, new: true }).lean();
    if (!t.enabled || !t.lastAt) return res.json({ ok: true, enabled: t.enabled, hasFix: false });
    res.json({ ok: true, enabled: true, hasFix: true, last: { lat: t.lastLat, lng: t.lastLng, heading: t.lastHeading, speed: t.lastSpeed, accuracy: t.lastAccuracy, at: t.lastAt } });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.get("/api/public/config", (_req, res) => { 
  res.json({ ok: true, mapboxPublicToken: MAPBOX_PUBLIC_TOKEN || "", canadaPostKey: CANADAPOST_KEY || "", 
  squareAppId: SQUARE_APP_ID, squareLocationId: SQUARE_LOCATION_ID, squareEnv: process.env.SQUARE_ENVIRONMENT || "sandbox",
  squareMembershipLinks: { standard: SQUARE_LINK_STANDARD, route: SQUARE_LINK_ROUTE, access: SQUARE_LINK_ACCESS, accesspro: SQUARE_LINK_ACCESSPRO } }); 
});
app.get("/api/public/memberships", (_req, res) => { res.json({ ok: true, plans: getPublicMembershipPlans() }); });

// =========================
// AUTH ROUTES
// =========================
app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) return res.status(500).send("Google auth is not configured on this server.");
  const state = String(req.query.returnTo || "").trim() === "popup" ? "popup" : "home";
  return passport.authenticate("google", { scope: ["profile", "email"], state })(req, res, next);
});
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: PUBLIC_SITE_URL + "/?login=failed" }), async (req, res) => {
  if (String(req.query.state || "") === "popup") return res.send("<script>window.close();</script>");
  try { if (!isProfileComplete((await User.findById(req.user._id).lean())?.profile || {})) return res.redirect(PUBLIC_SITE_URL + "/?tab=account&onboarding=1"); } catch {}
  res.redirect(PUBLIC_SITE_URL + "/");
});
app.get("/logout", (req, res) => { req.session.destroy(() => res.redirect(String(req.query.returnTo || (PUBLIC_SITE_URL + "/")).trim())); });

// =========================
// API: ME + PROFILE
// =========================
app.get("/api/me", (req, res) => { const u = req.user; res.json({ ok: true, loggedIn: !!u, email: u?.email || null, name: u?.name || "", photo: u?.photo || "", membershipLevel: u?.membershipLevel || "none", membershipStatus: u?.membershipStatus || "inactive", effectiveMembershipTier: getEffectiveMemberTierForUser(u) || "", renewalDate: u?.renewalDate || null, profileComplete: isProfileComplete(u?.profile || {}), isAdmin: !!u?.email && isAdminEmail(u.email) }); });
app.get("/api/profile", requireLogin, async (req, res) => { const u = await User.findById(req.user._id).lean(); res.json({ ok: true, profile: u?.profile || {}, profileComplete: isProfileComplete(u?.profile || {}), email: u?.email || "", name: u?.name || "", photo: u?.photo || "" }); });
app.post("/api/profile", requireLogin, async (req, res) => {
  try {
    const b = req.body || {}; const u = await User.findById(req.user._id); if (!u) return res.status(404).json({ ok: false, error: "User not found" });
    const addresses = Array.isArray(b.addresses) ? b.addresses : [];
    const newProfile = {
      version: 1, fullName: String(b.fullName || "").trim(), preferredName: String(b.preferredName || "").trim(), phone: String(b.phone || "").trim(), altPhone: String(b.altPhone || "").trim(), contactPref: String(b.contactPref || "").trim(), contactAuth: yn(b.contactAuth),
      subsDefault: String(b.subsDefault || "").trim(), dropoffDefault: String(b.dropoffDefault || "").trim(), customerType: "", accessibility: "", dietary: "", notes: String(b.notes || "").trim(),
      addresses: addresses.map((a) => ({ id: String(a.id || "").trim() || String(Math.random()).slice(2), label: String(a.label || "").trim(), town: String(a.town || "").trim(), zone: String(a.zone || "").trim(), streetAddress: String(a.streetAddress || "").trim(), unit: String(a.unit || "").trim(), postalCode: String(a.postalCode || "").trim(), instructions: String(a.instructions || "").trim(), gateCode: String(a.gateCode || "").trim() })),
      defaultId: String(b.defaultId || "").trim(), consentTerms: yn(b.consentTerms), consentPrivacy: yn(b.consentPrivacy), consentMarketing: yn(b.consentMarketing),
    };
    if (!newProfile.defaultId && newProfile.addresses.length) newProfile.defaultId = newProfile.addresses[0].id;
    newProfile.complete = isProfileComplete(newProfile); newProfile.completedAt = newProfile.complete ? new Date().toISOString() : null;
    u.profile = newProfile; u.markModified("profile"); await u.save(); res.json({ ok: true, profileComplete: newProfile.complete === true, profile: newProfile });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// RUNS + ESTIMATOR
// =========================
app.get("/api/runs/active", async (_req, res) => {
  try {
    const runs = await ensureUpcomingRuns(); const now = nowTz(); const out = {};
    for (const type of ["local", "owen"]) {
      const run = runs[type]; const opensAt = dayjs(run.opensAt).tz(TZ); const cutoffAt = dayjs(run.cutoffAt).tz(TZ); const windowOpen = now.isAfter(opensAt) && now.isBefore(cutoffAt); const pointsRemaining = Math.max(0, (run.maxPoints || 10) - (run.bookedPoints || 0));
      out[type] = { runKey: run.runKey, type: run.type, maxPoints: run.maxPoints || 10, bookedPoints: run.bookedPoints || 0, bookedOrdersCount: run.bookedOrdersCount || 0, bookedFeesTotal: run.bookedFeesTotal || 0, pointsRemaining, isOpen: windowOpen && pointsRemaining > 0, opensAtLocal: fmtLocal(run.opensAt), cutoffAtLocal: fmtLocal(run.cutoffAt), meetsMinimums: meetsMinimums(run), minimumText: runMinimumConfig(type).minimumText, cutoffAtISO: run.cutoffAt, opensAtISO: run.opensAt };
    }
    res.json({ ok: true, runs: out });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});
app.post("/api/estimator", (req, res) => { try { const effectiveMemberTier = getEffectiveMemberTierForUser(req.user, req.body?.memberTier || ""); res.json({ ok: true, effectiveMemberTier, breakdown: computeFeeBreakdown({ ...(req.body || {}), memberTier: effectiveMemberTier, applyPerk: "yes" }) }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });

// =========================
// ORDERS WITH SQUARE SDK
// =========================
app.post("/api/orders", requireLogin, requireProfileComplete, upload.single("groceryFile"), async (req, res) => {
  try {
    const b = req.body || {}; const user = await User.findById(req.user._id).lean(); const profile = user?.profile || {}; const orderClass = String(b.orderClass || "grocery");
    if (!yn(b.consent_terms) || !yn(b.consent_accuracy) || (orderClass === "grocery" && !yn(b.consent_dropoff))) return res.status(400).json({ ok: false, error: "All required consents must be accepted." });

    const runs = await ensureUpcomingRuns(); const runType = String(b.runType || ""); const run = runs[runType]; if (!run) return res.status(400).json({ ok: false, error: "Invalid runType." });
    const now = nowTz(); const opensAt = dayjs(run.opensAt).tz(TZ); const cutoffAt = dayjs(run.cutoffAt).tz(TZ);
    if (!(now.isAfter(opensAt) && now.isBefore(cutoffAt))) return res.status(403).json({ ok: false, error: "Ordering is closed for this run." });

    const fullName = String(b.fullName || profile.fullName || user.name || "").trim(); const phone = String(b.phone || profile.phone || "").trim();
    let spacePoints = 1; let required = [["fullName", fullName], ["phone", phone], ["runType", runType]];
    
    if (orderClass === "ride") {
      spacePoints = 3; required.push(["ridePickup", b.ridePickup], ["rideDestination", b.rideDestination]);
    } else {
      if (yn(b.addon_bulky)) spacePoints += 1;
      required.push(["town", b.town], ["streetAddress", b.streetAddress], ["postalCode", b.postalCode], ["zone", b.zone], ["primaryStore", b.primaryStore], ["groceryList", b.groceryList], ["dropoffPref", b.dropoffPref], ["subsPref", b.subsPref], ["contactPref", b.contactPref]);
    }
    for (const [k, v] of required) { if (!String(v || "").trim()) return res.status(400).json({ ok: false, error: "Missing required field: " + k }); }

    if ((run.bookedPoints || 0) + spacePoints > (run.maxPoints || 10)) return res.status(409).json({ ok: false, error: `Vehicle capacity reached! This order requires ${spacePoints} space points, but the Jeep is too full.` });

    const orderId = await nextOrderId(runType, run.runKey); const effectiveMemberTier = getEffectiveMemberTierForUser(user, "");
    const pricingSnapshot = computeFeeBreakdown({ orderClass, zone: b.zone, runType, extraStores: safeJsonArray(b.extraStores), grocerySubtotal: Number(b.grocerySubtotal || 0), addon_printing: b.addon_printing || "no", printPages: Number(b.printPages || 0), memberTier: effectiveMemberTier, applyPerk: "yes" }).totals;

    let squarePaymentId = "";
    let paymentStatus = "unpaid";
    if (b.paymentSourceId && squareClient) {
      let holdAmount = pricingSnapshot.totalFees;
      if (orderClass === "grocery") {
         const grocSub = Number(b.grocerySubtotal || 0);
         holdAmount += (grocSub * 1.15); // 15% buffer
      }
      const holdCents = Math.round(holdAmount * 100);
      try {
        const sqRes = await squareClient.paymentsApi.createPayment({
          sourceId: b.paymentSourceId,
          idempotencyKey: crypto.randomBytes(12).toString('hex'),
          amountMoney: { amount: holdCents, currency: "CAD" },
          autocomplete: false, 
          locationId: SQUARE_LOCATION_ID
        });
        squarePaymentId = sqRes.result.payment.id;
        paymentStatus = "authorized";
      } catch (err) {
        return res.status(400).json({ ok: false, error: "Credit card authorization failed. Please try another card." });
      }
    }

    await Run.updateOne({ runKey: run.runKey }, { $inc: { bookedOrdersCount: 1, bookedFeesTotal: pricingSnapshot.totalFees, bookedPoints: spacePoints }, $set: { lastRecalcAt: new Date() } });

    const created = await Order.create({
      orderId, orderClass, runKey: run.runKey, runType, spacePoints, hold: false,
      flags: { prescription: yn(b.addon_prescription), alcohol: yn(b.addon_liquor), bulky: yn(b.addon_bulky), idRequired: yn(b.addon_liquor) },
      customer: { fullName, email: String(user.email || "").trim().toLowerCase(), phone, altPhone: String(b.altPhone || "").trim(), dob: String(b.dob || "").trim() },
      address: { town: String(b.town || ""), streetAddress: String(b.streetAddress || ""), unit: String(b.unit || ""), postalCode: String(b.postalCode || ""), zone: String(b.zone || "") }, 
      stores: { primary: String(b.primaryStore || ""), extra: safeJsonArray(b.extraStores) }, preferences: { dropoffPref: String(b.dropoffPref || ""), subsPref: String(b.subsPref || ""), contactPref: String(b.contactPref || ""), contactAuth: true },
      addOns: { prescription: { requested: yn(b.addon_prescription), pharmacyName: String(b.prescriptionPharmacy || ""), notes: String(b.prescriptionNotes || "") }, liquor: { requested: yn(b.addon_liquor), storeName: String(b.liquorStore || ""), notes: String(b.liquorNotes || ""), idRequired: true }, printing: { requested: yn(b.addon_printing), pages: Math.max(0, Number(b.printPages || 0)), notes: String(b.printingNotes || "") }, fastFood: { requested: yn(b.addon_fastfood), restaurant: String(b.fastFoodRestaurant || ""), orderDetails: String(b.fastFoodOrder || "") }, parcel: { requested: yn(b.addon_parcel), carrier: String(b.parcelCarrier || ""), details: String(b.parcelDetails || "") }, bulky: { requested: yn(b.addon_bulky), details: String(b.bulkyDetails || "") }, ride: { requested: orderClass === "ride", pickupAddress: String(b.ridePickup || ""), destination: String(b.rideDestination || ""), preferredWindow: String(b.rideWindow || ""), notes: String(b.rideNotes || "") }, generalNotes: String(b.optionalNotes || "") },
      deliveryMeta: { gateCode: String(b.gateCode || ""), buildingAccessNotes: String(b.buildingAccessNotes || ""), parkingNotes: String(b.parkingNotes || ""), budgetCap: Math.max(0, Number(b.budgetCap || 0)), receiptPreference: String(b.receiptPreference || ""), photoProofOk: yn(b.photoProofOk) },
      list: { groceryListText: String(b.groceryList || ""), attachment: req.file ? { originalName: req.file.originalname, mimeType: req.file.mimetype, size: req.file.size, path: req.file.path } : null }, 
      consents: { terms: true, accuracy: true, dropoff: yn(b.consent_dropoff) }, pricingSnapshot,
      payments: { fees: { status: "unpaid" }, groceries: { status: paymentStatus, squarePaymentId } }, 
      status: { state: "submitted", note: "", updatedAt: new Date(), updatedBy: "customer" }, statusHistory: [{ state: "submitted", note: "", at: new Date(), by: "customer" }],
      adminLog: [{ at: new Date(), by: "system", action: "order_created", meta: { runKey: run.runKey, effectiveMemberTier, orderClass } }],
    });

    res.json({ ok: true, orderId, runKey: run.runKey, cancelToken: signCancelToken(orderId, cutoffAt.toDate().getTime()), cancelUntilLocal: fmtLocal(cutoffAt.toDate()), effectiveMemberTier });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/orders/:orderId/cancel", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const order = await Order.findOne({ orderId }); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    const run = await Run.findOne({ runKey: order.runKey }).lean(); if (!run?.cutoffAt) return res.status(500).json({ ok: false, error: "Run cutoff not available" });
    if (!ACTIVE_STATES.has(order.status?.state || "submitted")) return res.status(400).json({ ok: false, error: "Order cannot be cancelled in its current status." });
    if (!verifyCancelToken(orderId, String(req.body?.token || "").trim()).ok) return res.status(403).json({ ok: false, error: "Invalid cancel token." });
    if (!nowTz().isBefore(dayjs(run.cutoffAt).tz(TZ))) return res.status(403).json({ ok: false, error: "Cancellation window closed." });

    if (order.payments.groceries.squarePaymentId && order.payments.groceries.status === "authorized" && squareClient) {
      try { await squareClient.paymentsApi.cancelPayment(order.payments.groceries.squarePaymentId); } catch(err) { console.error("Square void failed on cancel:", err); }
      order.payments.groceries.status = "voided";
    }

    await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -Number(order.pricingSnapshot?.totalFees || 0), bookedPoints: -Number(order.spacePoints || 1) }, $set: { lastRecalcAt: new Date() } });
    order.status.state = "cancelled"; order.status.note = "Cancelled by customer"; order.status.updatedAt = new Date(); order.status.updatedBy = "customer";
    order.statusHistory.push({ state: "cancelled", note: "Cancelled by customer", at: new Date(), by: "customer" }); 
    await order.save(); return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// ADMIN: FETCH ORDERS API
// =========================
app.get("/api/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const state = String(req.query.state || "").trim();
    const runKey = String(req.query.runKey || "").trim();
    const limit = Math.min(Number(req.query.limit || 200), 500);

    const filter = {};
    if (state) filter["status.state"] = state;
    if (runKey) filter.runKey = runKey;
    if (q) {
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [
        { orderId: re },
        { "customer.fullName": re },
        { "customer.email": re },
        { "customer.phone": re },
        { "address.streetAddress": re }
      ];
    }

    const items = await Order.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const order = await Order.findOne({ orderId }).lean();
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    res.json({ ok: true, order });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// SQUARE FINAL CAPTURE (ADMIN ONLY)
app.post("/api/admin/orders/:orderId/capture", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase();
    const finalGroceryTotal = Number(req.body.finalGroceryTotal || 0);
    const order = await Order.findOne({ orderId });
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    const finalAmount = finalGroceryTotal + Number(order.pricingSnapshot.totalFees || 0);
    const finalCents = Math.round(finalAmount * 100);

    if (order.payments.groceries.squarePaymentId && order.payments.groceries.status === "authorized") {
       if (!squareClient) throw new Error("Square client not configured on server.");
       await squareClient.paymentsApi.completePayment(order.payments.groceries.squarePaymentId, {
         amountMoney: { amount: finalCents, currency: "CAD" }
       });
    }

    order.payments.groceries.status = "paid"; order.payments.fees.status = "paid";
    order.payments.groceries.note = "Exact grocery total: $" + finalGroceryTotal.toFixed(2);
    order.status.state = "out_for_delivery"; order.status.updatedAt = new Date(); order.status.updatedBy = adminBy(req);
    order.statusHistory.push({ state: "out_for_delivery", note: "Payment finalized, driver dispatched", at: new Date(), by: adminBy(req) });
    await order.save();

    const phone = order.customer?.phone; const firstName = order.customer?.fullName?.split(' ')[0] || 'there';
    if (phone) {
       const run = await Run.findOne({ runKey: order.runKey }).lean(); let trackingLink = "";
       if (run) trackingLink = `${PUBLIC_SITE_URL}/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(signTrackingToken(order.orderId, run.runKey, dayjs(run.cutoffAt).add(1, "day").valueOf()))}&orderId=${encodeURIComponent(order.orderId)}`;
       const smsMessage = `Hi ${firstName}, your groceries are packed! The exact receipt total was $${finalGroceryTotal.toFixed(2)}. We have finalized your payment and released the remaining hold. I'm on my way to drop off your order! 🚙💨 Track live: ${trackingLink}`;
       await sendSms(phone, smsMessage);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/admin/orders/:orderId/status", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const state = String(req.body?.state || "").trim(); const note = String(req.body?.note || "").trim(); const by = adminBy(req);
    if (!AllowedStates.includes(state)) return res.status(400).json({ ok: false, error: "Invalid state" });
    const order = await Order.findOne({ orderId }); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    const oldState = order.status.state; order.status.state = state; order.status.note = note; order.status.updatedAt = new Date(); order.status.updatedBy = by; order.statusHistory.push({ state, note, at: new Date(), by });
    await order.save(); 

    if (oldState !== state) {
      const phone = order.customer?.phone; const firstName = order.customer?.fullName?.split(' ')[0] || 'there';
      if (phone) {
        let smsMessage = "";
        if (state === "shopping") smsMessage = `Hi ${firstName}! I've grabbed a cart and I'm officially picking your groceries. Let's hope the avocados are cooperating today. 🥑 - Tobermory Grocery Run`;
        else if (state === "out_for_delivery") {
          const run = await Run.findOne({ runKey: order.runKey }).lean(); let trackingLink = "";
          if (run) trackingLink = `${PUBLIC_SITE_URL}/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(signTrackingToken(order.orderId, run.runKey, dayjs(run.cutoffAt).add(1, "day").valueOf()))}&orderId=${encodeURIComponent(order.orderId)}`;
          smsMessage = `Hi ${firstName}, the Jeep is loaded and I'm on the road! Track your delivery live right here: ${trackingLink} 🚙💨 - TGR`;
        } 
        else if (state === "delivered") smsMessage = `Mission accomplished! Your order has been dropped off. Enjoy the goodies, and thanks for trusting Tobermory Grocery Run! 🛒✨`;
        if (smsMessage) await sendSms(phone, smsMessage);
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/admin/orders/:orderId/payments", requireLogin, requireAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({ orderId: String(req.params.orderId || "").trim().toUpperCase() }); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    const fs = String(req.body?.feesStatus || "").trim(); const gs = String(req.body?.groceriesStatus || "").trim();
    if (fs) { order.payments.fees.status = fs; order.payments.fees.paidAt = fs === "paid" ? new Date() : null; }
    if (gs) { order.payments.groceries.status = gs; order.payments.groceries.paidAt = (gs === "paid" || gs === "deposit_paid") ? new Date() : null; }
    if (req.body?.note) { order.payments.fees.note = String(req.body.note).trim(); order.payments.groceries.note = String(req.body.note).trim(); }
    await order.save(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.delete("/api/admin/orders/:orderId", requireLogin, requireAdmin, async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim().toUpperCase(); const order = await Order.findOne({ orderId }).lean(); if (!order) return res.status(404).json({ ok: false, error: "Order not found" });
    if (ACTIVE_STATES.has(order.status?.state || "submitted")) await Run.updateOne({ runKey: order.runKey }, { $inc: { bookedOrdersCount: -1, bookedFeesTotal: -Number(order.pricingSnapshot?.totalFees || 0), bookedPoints: -Number(order.spacePoints || 1) }, $set: { lastRecalcAt: new Date() } });
    await Order.deleteOne({ orderId }); res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

app.post("/api/admin/tracking/:runKey/start", requireLogin, requireAdmin, async (req, res) => { try { const runKey = String(req.params.runKey || "").trim(); await ensureTrackingDoc(runKey); await Tracking.updateOne({ runKey }, { $set: { enabled: true, startedAt: new Date(), stoppedAt: null, updatedBy: adminBy(req) } }); res.json({ ok: true, runKey }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.post("/api/admin/tracking/:runKey/stop", requireLogin, requireAdmin, async (req, res) => { try { const runKey = String(req.params.runKey || "").trim(); await ensureTrackingDoc(runKey); await Tracking.updateOne({ runKey }, { $set: { enabled: false, stoppedAt: new Date(), updatedBy: adminBy(req) } }); res.json({ ok: true, runKey }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.post("/api/admin/tracking/:runKey/update", requireLogin, requireAdmin, async (req, res) => { try { const runKey = String(req.params.runKey || "").trim(); const lat = Number(req.body?.lat); const lng = Number(req.body?.lng); if (!Number.isFinite(lat) || !Number.isFinite(lng)) return res.status(400).json({ ok: false, error: "lat/lng required" }); await ensureTrackingDoc(runKey); await Tracking.updateOne({ runKey }, { $set: { lastLat: lat, lastLng: lng, lastHeading: Number.isFinite(Number(req.body?.heading)) ? Number(req.body?.heading) : null, lastSpeed: Number.isFinite(Number(req.body?.speed)) ? Number(req.body?.speed) : null, lastAccuracy: Number.isFinite(Number(req.body?.accuracy)) ? Number(req.body?.accuracy) : null, lastAt: new Date(), updatedBy: adminBy(req) } }); res.json({ ok: true }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });
app.get("/api/admin/orders/:orderId/tracking-link", requireLogin, requireAdmin, async (req, res) => { try { const orderId = String(req.params.orderId || "").trim().toUpperCase(); const o = await Order.findOne({ orderId }).lean(); if (!o) return res.status(404).json({ ok: false, error: "Order not found" }); const run = await Run.findOne({ runKey: o.runKey }).lean(); if (!run) return res.status(404).json({ ok: false, error: "Run not found" }); res.json({ ok: true, url: `${PUBLIC_SITE_URL}/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(signTrackingToken(o.orderId, run.runKey, dayjs(run.cutoffAt).add(1, "day").valueOf()))}&orderId=${encodeURIComponent(o.orderId)}` }); } catch (e) { res.status(500).json({ ok: false, error: String(e) }); } });

// =========================
// MEMBER PORTAL
// =========================
app.get("/member", requireLogin, async (req, res) => {
  try {
    const email = String(req.user?.email || "").toLowerCase().trim(); const name = String(req.user?.name || "").trim();
    const orders = await Order.find({ "customer.email": email }).sort({ createdAt: -1 }).limit(80).lean();
    const runKeys = Array.from(new Set(orders.map(o => o.runKey).filter(Boolean)));
    const runs = await Run.find({ runKey: { $in: runKeys } }).lean(); const runByKey = new Map(runs.map(r => [r.runKey, r]));
    const now = nowTz(); const trackables = [];
    for (const o of orders) {
      const status = o.status?.state || "submitted"; if (!ACTIVE_STATES.has(status)) continue;
      const run = runByKey.get(o.runKey); if (!run?.runKey || !run?.cutoffAt) continue;
      const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf(); const tkn = signTrackingToken(o.orderId, run.runKey, expMs);
      trackables.push({ orderId: o.orderId, runKey: run.runKey, token: tkn, status });
    }

    const rows = orders.map(o => {
      const fees = typeof o.pricingSnapshot?.totalFees === "number" ? o.pricingSnapshot.totalFees.toFixed(2) : "0.00";
      const status = o.status?.state || "submitted"; const run = runByKey.get(o.runKey);
      const cutoffAt = run?.cutoffAt ? dayjs(run.cutoffAt).tz(TZ) : null; const cancelOpen = cutoffAt ? now.isBefore(cutoffAt) : false;
      let cancelHtml = `<span class="muted">—</span>`;
      if (ACTIVE_STATES.has(status) && cancelOpen) { const token = signCancelToken(o.orderId, cutoffAt.toDate().getTime()); cancelHtml = `<button class="btn" data-cancel="${escapeHtml(o.orderId)}" data-token="${escapeHtml(token)}">Cancel</button>`; }
      else if (status === "cancelled") { cancelHtml = `<span class="pill">Cancelled</span>`; }
      else if (!cancelOpen && ACTIVE_STATES.has(status)) { cancelHtml = `<span class="muted">Past cutoff</span>`; }

      let trackHtml = `<span class="muted">—</span>`;
      if (ACTIVE_STATES.has(status) && run?.runKey && run?.cutoffAt) {
        const expMs = dayjs(run.cutoffAt).add(1, "day").valueOf(); const tkn = signTrackingToken(o.orderId, run.runKey, expMs);
        const link = `https://api.tobermorygroceryrun.ca/member?trackRunKey=${encodeURIComponent(run.runKey)}&token=${encodeURIComponent(tkn)}&orderId=${encodeURIComponent(o.orderId)}`;
        trackHtml = `<button class="btn" data-track-run="${escapeHtml(run.runKey)}" data-track-token="${escapeHtml(tkn)}" data-track-order="${escapeHtml(o.orderId)}">Track on map</button> <button class="btn" data-copy="${escapeHtml(link)}">Copy link</button>`;
      }
      const addr = `${o.address?.streetAddress || ""}${o.address?.unit ? " " + o.address.unit : ""}, ${o.address?.town || ""}, ON ${o.address?.postalCode || ""}`.trim();
      return `<tr><td><div style="font-weight:1000;">${escapeHtml(o.orderId)}</div><div class="muted" style="font-size:12px;">${escapeHtml(fmtLocal(o.createdAt))}</div></td><td><div style="font-weight:900;">${escapeHtml(addr)}</div><div class="muted" style="font-size:12px;">Zone ${escapeHtml(o.address?.zone || "")}</div></td><td><span class="pill">${escapeHtml(o.runType || "")}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.runKey || "")}</div></td><td><span class="pill">${escapeHtml(status)}</span><div class="muted" style="font-size:12px;margin-top:4px;">${escapeHtml(o.status?.note || "")}</div></td><td>$${escapeHtml(fees)}</td><td>${trackHtml}</td><td>${cancelHtml}</td></tr>`;
    }).join("");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`<!doctype html><html lang="en-CA"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TGR Member Portal</title><style>:root{--bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14); --text:#fff; --muted:rgba(255,255,255,.75); --red:#e3342f; --red2:#ff4a44; --radius:14px;} body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;} .wrap{max-width:1250px;margin:0 auto;padding:16px;} .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;} .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;} .btn{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-weight:900;border-radius:999px;padding:10px 14px;cursor:pointer;text-decoration:none;white-space:nowrap;} .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);} .btn.ghost{background:transparent;} .muted{color:var(--muted);} .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;} table{width:100%;border-collapse:collapse;} th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;} th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;letter-spacing:.08em;text-align:left;} .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;} .toast.show{display:block;} .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;} .grid{display:grid;grid-template-columns: 1fr 1fr; gap:12px;} @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} } #mapWrap{display:none;} #map{height: 420px; border-radius: 14px; border:1px solid rgba(255,255,255,.14); overflow:hidden;} .small{font-size:13px;} .warn{border:1px solid rgba(227,52,47,.45);background:rgba(227,52,47,.12);border-radius:12px;padding:10px 12px;}</style></head><body><div class="wrap"><div class="card"><div class="row" style="justify-content:space-between;"><div><div style="font-weight:1000;font-size:22px;">Member Portal</div><div class="muted">Signed in as <strong>${escapeHtml(email)}</strong>${name ? ` • ${escapeHtml(name)}` : ""}</div></div><div class="row"><a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a><a class="btn" href="${escapeHtml(SQUARE_PAY_GROCERIES_LINK)}" target="_blank" rel="noopener">Pay Grocery Total</a><a class="btn" href="${escapeHtml(SQUARE_PAY_FEES_LINK)}" target="_blank" rel="noopener">Pay Service & Delivery Fees</a><a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a></div></div><div class="toast" id="toast"></div>

<div class="hr"></div>

<div class="card" style="box-shadow:none; border: 1px solid rgba(227,52,47,.45); background: rgba(227,52,47,.08); margin-bottom:14px;">
  <div style="font-weight:1000;font-size:18px;">My Membership</div>
  <div class="muted small" style="margin-bottom:10px;">Your active perks are automatically applied to your orders at checkout.</div>
  <div class="row">
    <div style="flex:1 1 150px;">
       <div class="muted small">Current Tier</div>
       <div style="font-size:22px; font-weight:900; text-transform:capitalize;">${escapeHtml(req.user?.membershipLevel && req.user.membershipLevel !== 'none' ? req.user.membershipLevel : 'No active plan')}</div>
    </div>
    <div style="flex:1 1 150px;">
       <div class="muted small">Status</div>
       <div style="font-size:22px; font-weight:900; text-transform:capitalize;">${escapeHtml(req.user?.membershipStatus || 'Inactive')}</div>
    </div>
    <div style="flex:1 1 200px;">
       <div class="muted small">Renews On</div>
       <div style="font-size:22px; font-weight:900;">${req.user?.renewalDate ? new Date(req.user.renewalDate).toLocaleDateString() : '—'}</div>
    </div>
  </div>
  <div class="row" style="margin-top:14px;">
     <a class="btn primary small" href="${escapeHtml(PUBLIC_SITE_URL)}/?tab=memberships">Upgrade / Renew Plan</a>
  </div>
</div>

<div class="grid" id="mapWrap"><div class="card" style="box-shadow:none;"><div style="font-weight:1000;font-size:18px;">Live Tracking Map</div><div class="muted small" id="mapSub">Select an order to track. Tracking only works when enabled for the run.</div><div class="hr"></div><div id="map"></div><div class="hr"></div><div class="row"><span class="pill" id="mapStatus">—</span><span class="pill" id="mapLast">Last: —</span><button class="btn" id="stopMap">Stop</button></div><div class="muted small" id="mapErr" style="margin-top:10px;"></div></div><div class="card" style="box-shadow:none;"><div style="font-weight:1000;font-size:18px;">Tracking controls</div><div class="muted small">Only your active orders can track. If tracking is disabled, you’ll see “Tracking off”.</div><div class="hr"></div><div class="warn"><div style="font-weight:1000;">Tip</div><div class="muted small">If your map is blank, the driver hasn’t started tracking or hasn’t sent a GPS fix yet.</div></div></div></div><div class="hr"></div><div style="overflow:auto;"><table><thead><tr><th>Order</th><th>Address</th><th>Run</th><th>Status</th><th>Fees</th><th>Tracking</th><th>Cancel</th></tr></thead><tbody>${rows || `<tr><td colspan="7" class="muted">No orders yet.</td></tr>`}</tbody></table></div></div></div><script>const TRACKABLES = ${JSON.stringify(trackables)}; let MAPBOX_TOKEN = ""; let map = null; let marker = null; let pollTimer = null; let activeTrack = null; const toast = (msg)=>{const el = document.getElementById("toast"); el.textContent = msg; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"), 3500);}; async function cancelOrder(orderId, token){const ok = confirm("Cancel " + orderId + " before cutoff?"); if(!ok) return; const r = await fetch("/api/orders/" + encodeURIComponent(orderId) + "/cancel", {method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify({ token })}); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false) return toast(d.error || "Cancel failed"); toast("Cancelled " + orderId); setTimeout(()=>location.reload(), 700);} async function copy(text){try{ await navigator.clipboard.writeText(text); return true; } catch { return false; }} document.querySelectorAll("[data-cancel]").forEach(btn=>{btn.addEventListener("click", ()=>{cancelOrder(btn.getAttribute("data-cancel"), btn.getAttribute("data-token"));});}); document.querySelectorAll("[data-copy]").forEach(btn=>{btn.addEventListener("click", async ()=>{const url = btn.getAttribute("data-copy"); if (await copy(url)) toast("Link copied ✅"); else toast("Copy failed");});}); document.querySelectorAll("[data-track-run]").forEach(btn=>{btn.addEventListener("click", ()=>{const runKey = btn.getAttribute("data-track-run"); const token = btn.getAttribute("data-track-token"); const orderId = btn.getAttribute("data-track-order"); startMapTracking({ runKey, token, orderId });});}); document.getElementById("stopMap").addEventListener("click", ()=> stopMapTracking()); function qs(){const u = new URL(location.href); return {runKey: u.searchParams.get("trackRunKey") || "", token: u.searchParams.get("token") || "", orderId: u.searchParams.get("orderId") || ""};} async function loadConfig(){const r = await fetch("/api/public/config"); const d = await r.json().catch(()=>({})); if(r.ok && d.ok) MAPBOX_TOKEN = d.mapboxPublicToken || "";} function setMapWrap(show){document.getElementById("mapWrap").style.display = show ? "grid" : "none";} function setStatus(text){ document.getElementById("mapStatus").textContent = text; } function setLast(text){ document.getElementById("mapLast").textContent = text; } function setErr(text){ document.getElementById("mapErr").textContent = text || ""; } function loadMapboxLib(){return new Promise((resolve, reject)=>{if (window.mapboxgl) return resolve(); const css = document.createElement("link"); css.rel = "stylesheet"; css.href = "https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.css"; document.head.appendChild(css); const s = document.createElement("script"); s.src = "https://api.mapbox.com/mapbox-gl-js/v2.15.0/mapbox-gl.js"; s.onload = ()=> resolve(); s.onerror = ()=> reject(new Error("Mapbox failed to load")); document.head.appendChild(s);});} async function ensureMap(){if (map) return; if (!MAPBOX_TOKEN) throw new Error("Mapbox token missing on server"); await loadMapboxLib(); mapboxgl.accessToken = MAPBOX_TOKEN; map = new mapboxgl.Map({container: "map", style: "mapbox://styles/mapbox/dark-v11", center: [-81.7, 45.25], zoom: 9}); marker = new mapboxgl.Marker({ color: "#ff4a44" }).setLngLat([-81.7, 45.25]).addTo(map);} function stopMapTracking(){activeTrack = null; if (pollTimer) clearInterval(pollTimer); pollTimer = null; setStatus("—"); setLast("Last: —"); setErr(""); toast("Tracking stopped");} async function pollOnce(){if (!activeTrack) return; const { runKey, token } = activeTrack; try{const r = await fetch("/api/public/tracking/" + encodeURIComponent(runKey) + "?token=" + encodeURIComponent(token)); const d = await r.json().catch(()=>({})); if(!r.ok || d.ok===false){setStatus("Error"); setErr(d.error || "Tracking error"); return;} if (!d.enabled){setStatus("Tracking off"); setErr("Tracking is not enabled for this run yet."); return;} if (!d.hasFix){setStatus("Waiting for GPS"); setErr("No GPS fix yet. Try again in a moment."); return;} const lat = d.last.lat; const lng = d.last.lng; const at = d.last.at ? new Date(d.last.at).toLocaleString() : "—"; setStatus("Live ✅"); setLast("Last: " + at); setErr(""); marker.setLngLat([lng, lat]); map.easeTo({ center: [lng, lat], zoom: 12, duration: 900 });} catch (e){setStatus("Error"); setErr(String(e.message || e));}} async function startMapTracking(t){activeTrack = t; setMapWrap(true); setStatus("Loading…"); setLast("Last: —"); setErr(""); document.getElementById("mapSub").textContent = "Tracking " + (t.orderId || "") + " • " + (t.runKey || ""); try{await ensureMap(); await pollOnce(); if (pollTimer) clearInterval(pollTimer); pollTimer = setInterval(pollOnce, 2500); toast("Map tracking started ✅");} catch (e){setStatus("Error"); setErr(String(e.message || e));}} (async function boot(){await loadConfig(); const p = qs(); if (p.runKey && p.token) {startMapTracking({ runKey: p.runKey, token: p.token, orderId: p.orderId || "" }); return;} setMapWrap(false);})();</script></body></html>`);
  } catch (e) { res.status(500).send("Member portal error: " + String(e)); }
});

app.get("/api/admin/runs/:runKey/master-list", requireLogin, requireAdmin, async (req, res) => {
  try {
    const runKey = String(req.params.runKey || "").trim();
    const orders = await Order.find({ runKey, "status.state": { $in: ["submitted", "confirmed", "shopping", "packed"] } }).lean();
    const tally = {}; const extraStops = [];
    for (const o of orders) {
      if (o.orderClass === "ride") continue; 
      if (o.list && o.list.groceryListText) {
        for (const line of o.list.groceryListText.split(/\r?\n/)) {
          let text = line.replace(/^•\s*/, '').trim(); if (!text) continue;
          if (!tally[text.toLowerCase()]) tally[text.toLowerCase()] = { name: text, count: 0 };
          tally[text.toLowerCase()].count += 1;
        }
      }
      if (o.stores && Array.isArray(o.stores.extra)) o.stores.extra.forEach(stop => { if(stop.trim()) extraStops.push(`${stop.trim()} (Order: ${o.orderId})`); });
    }
    res.json({ ok: true, runKey, items: Object.values(tally).sort((a, b) => a.name.localeCompare(b.name)), extraStops });
  } catch(e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// =========================
// ADMIN PAGE (Includes Magic Capture UI)
// =========================
app.get("/admin", requireLogin, requireAdmin, async (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TGR Admin</title>
<style>
  :root{ --bg:#0b0b0b; --panel:rgba(255,255,255,.06); --line:rgba(255,255,255,.14); --text:#fff; --muted:rgba(255,255,255,.75); --red:#e3342f; --red2:#ff4a44; --radius:14px; }
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
  .wrap{max-width:1400px;margin:0 auto;padding:16px;}
  .card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius);padding:14px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .btn{border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-weight:900;border-radius:999px;padding:10px 14px;cursor:pointer;text-decoration:none;white-space:nowrap;}
  .btn.primary{background:linear-gradient(180deg,var(--red2),var(--red));border-color:rgba(0,0,0,.25);}
  .btn.ghost{background:transparent;} .muted{color:var(--muted);}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);font-weight:900;font-size:12px;}
  .hr{height:1px;background:rgba(255,255,255,.12);margin:12px 0;}
  input,select,textarea{width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.22);color:#fff;font-size:15px;outline:none;}
  table{width:100%;border-collapse:collapse;} th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.12);vertical-align:top;} th{font-size:12px;color:rgba(255,255,255,.72);text-transform:uppercase;text-align:left;}
  .grid{display:grid;grid-template-columns: 1.1fr .9fr; gap:12px;} @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} }
  .toast{margin-top:10px;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.18);background:rgba(0,0,0,.24);display:none;font-weight:900;} .toast.show{display:block;}
  .modalBack{position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; align-items:center; justify-content:center; padding:16px; z-index:100;}
  .modal{width:min(980px, 100%); max-height:92vh; overflow:auto; border:1px solid rgba(255,255,255,.16); background:#0b0b0b; border-radius:16px; padding:14px;}
  .k{font-size:12px;color:rgba(255,255,255,.7);text-transform:uppercase;letter-spacing:.08em;} .v{font-weight:900;} .two{display:grid;grid-template-columns:1fr 1fr; gap:10px;}
  @media print { body * { visibility: hidden; } #masterListModalBack, #masterListModalBack * { visibility: visible; } #masterListModalBack { position: absolute; left: 0; top: 0; background: white; color: black; align-items: flex-start; } .modal { border: none; background: white; box-shadow: none; overflow: visible; max-height: none; } .btn, .toast { display: none !important; } .card { background: white !important; border: none !important; color: black !important; } pre { color: black !important; font-family: monospace; font-size: 14pt; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between;">
      <div><div style="font-weight:1000;font-size:22px;">Admin Command Center</div><div class="muted">Manage orders, tracking, and grocery catalogue.</div></div>
      <div class="row"><a class="btn ghost" href="${escapeHtml(PUBLIC_SITE_URL)}/">Back to site</a><a class="btn" href="/admin/tracking-control">Tracking Control</a><a class="btn ghost" href="/logout?returnTo=${encodeURIComponent(PUBLIC_SITE_URL + "/")}">Log out</a></div>
    </div>
    <div class="toast" id="toast"></div><div class="hr" style="margin-top:16px; margin-bottom:16px;"></div>
    <div class="row" style="margin-bottom:14px;"><button class="btn primary" id="tabBtnOrders" onclick="switchTab('orders')">Orders Management</button><button class="btn" id="tabBtnCatalogue" onclick="switchTab('catalogue')">Catalogue / Inventory</button></div>

    <div id="tabContentOrders">
      <div class="grid">
        <div class="card" style="box-shadow:none;">
          <div style="font-weight:1000;">Search / Filters</div><div class="hr"></div>
          <div class="row"><div style="flex: 2 1 320px;"><label class="muted" style="font-weight:900;">Search</label><input id="q" placeholder="orderId, name, email, phone, address" /></div><div style="flex: 1 1 180px;"><label class="muted" style="font-weight:900;">State</label><select id="state"><option value="">Any</option><option>submitted</option><option>confirmed</option><option>shopping</option><option>packed</option><option>out_for_delivery</option><option>delivered</option><option>issue</option><option>cancelled</option></select></div><div style="flex: 1 1 180px;"><label class="muted" style="font-weight:900;">Run Key</label><input id="runKey" placeholder="YYYY-MM-DD-local" /></div></div>
          <div class="row" style="margin-top:8px;"><button class="btn primary" id="searchBtn">Search</button><button class="btn ghost" id="clearBtn">Clear</button><span class="pill" id="countPill">—</span></div>
        </div>
        <div class="card" style="box-shadow:none;">
          <div style="font-weight:1000;">Quick Tools</div><div class="hr"></div>
          <div class="row" style="margin-top:10px;"><div style="flex:1 1 200px;"><input id="toolRunKey" placeholder="YYYY-MM-DD-local" /></div><button class="btn" id="exportBtn">Download CSV</button><button class="btn primary" id="masterListBtn">Master Shopping List</button></div>
        </div>
      </div>
      <div class="hr"></div>
      <div style="overflow:auto;"><table><thead><tr><th>Order</th><th>Customer</th><th>Address</th><th>Run</th><th>Status</th><th>Fees</th><th>Actions</th></tr></thead><tbody id="rows"><tr><td colspan="7" class="muted">Loading…</td></tr></tbody></table></div>
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
        <div class="k">Address</div><div class="v" id="m_addr">—</div>
        <div class="k">Run</div><div class="v" id="m_run">—</div>
      </div>
      <div class="card" style="box-shadow:none;">
        <div class="k">Fees total</div><div class="v" id="m_fees">—</div>
        <div class="k">Square Payment Status</div><div class="v" id="m_groceriesCurrent">—</div><div class="hr"></div>
        
        <div class="card" style="box-shadow:none; border: 1px solid rgba(227,52,47,.45) !important; background: rgba(227,52,47,.1) !important; margin-bottom:14px;">
          <div class="k" style="color: #ff4a44;">Finalize Payment (Delayed Capture)</div>
          <div class="muted small" style="margin-bottom:8px;">Enter exact receipt total. This captures the exact amount via Square and texts the customer.</div>
          <div class="row">
            <input id="m_finalGroceryTotal" type="number" step="0.01" placeholder="Receipt total ($)" style="max-width:160px; background:rgba(0,0,0,.4);" />
            <button class="btn primary" id="m_captureBtn">Finalize & Dispatch 🚙</button>
          </div>
        </div>

        <label class="muted" style="font-weight:900;">Manual Status Override</label>
        <div class="row"><select id="m_state" style="max-width:180px;"><option>submitted</option><option>confirmed</option><option>shopping</option><option>packed</option><option>out_for_delivery</option><option>delivered</option><option>issue</option><option>cancelled</option></select><button class="btn ghost" id="m_saveState">Save override</button></div>
        <div class="row" style="margin-top:10px;"><button class="btn ghost" id="m_cancelAdmin">Cancel order</button><button class="btn ghost" id="m_deleteOrder">Delete order</button></div>
      </div>
    </div>
    <div class="hr"></div>
    <div class="two">
      <div class="card" style="box-shadow:none;"><div style="font-weight:1000;">Grocery list</div><div class="hr"></div><pre id="m_list"></pre></div>
      <div class="card" style="box-shadow:none;"><div style="font-weight:1000;">Add-ons / notes</div><div class="hr"></div><pre id="m_addons"></pre></div>
    </div>
  </div>
</div>

<script>
  const toast = (msg)=>{ const el = document.getElementById("toast"); el.textContent = msg; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"), 3500); };
  const qs = (k)=> document.getElementById(k);
  function switchTab(tab) { qs('tabContentOrders').style.display = tab === 'orders' ? 'block' : 'none'; }

  const rowsEl = qs("rows"); let modalOrder = null;
  function buildQuery(){ const p = new URLSearchParams(); const q = qs("q").value.trim(); const state = qs("state").value.trim(); const runKey = qs("runKey").value.trim(); if(q) p.set("q", q); if(state) p.set("state", state); if(runKey) p.set("runKey", runKey); p.set("limit","200"); return p.toString(); }
  function esc(s){ return String(s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"); }
  function money(n){ return Number(n||0).toFixed(2); }

  function render(items){
    const list = items || []; qs("countPill").textContent = "Results: " + list.length;
    if(!list.length){ rowsEl.innerHTML = '<tr><td colspan="7" class="muted">No results.</td></tr>'; return; }
    rowsEl.innerHTML = list.map(o=>{
      const id = esc(o.orderId); const cust = esc(o.customer?.fullName || ""); const phone = esc(o.customer?.phone || ""); const email = esc(o.customer?.email || ""); const addr = esc((o.address?.streetAddress||"") + ", " + (o.address?.town||"")); const run = esc(o.runKey || ""); const rt = esc(o.runType || ""); const st = esc(o.status?.state || ""); const fees = money(o.pricingSnapshot?.totalFees || 0);
      return \`<tr><td><div style="font-weight:1000;">\${id}</div><div class="muted" style="font-size:12px;">\${email}</div></td><td><div style="font-weight:900;">\${cust}</div><div class="muted" style="font-size:12px;">\${phone}</div></td><td>\${addr}</td><td><span class="pill">\${rt}</span><div class="muted" style="font-size:12px;margin-top:4px;">\${run}</div></td><td><span class="pill">\${st}</span></td><td>$\${fees}</td><td><button class="btn" data-open="\${id}">Open</button></td></tr>\`;
    }).join("");
    document.querySelectorAll("[data-open]").forEach(btn=>{ btn.addEventListener("click", ()=> openOrder(btn.getAttribute("data-open"))); });
  }

  async function search(){ rowsEl.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>'; try{ const r = await fetch("/api/admin/orders?" + buildQuery(), { credentials:"include" }); const d = await r.json(); render(d.items || []); } catch(e){ rowsEl.innerHTML = '<tr><td colspan="7" class="muted">Error: ' + esc(e) + '</td></tr>'; } }

  function openModal(show){ qs("modalBack").style.display = show ? "flex" : "none"; }
  function buildAddonsText(o){ const lines = []; if (o.addOns?.generalNotes) lines.push("General notes: " + o.addOns.generalNotes); return lines.length ? lines.join("\\n") : "—"; }

  async function openOrder(orderId){
    try{
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(orderId), { credentials:"include" }); const d = await r.json(); modalOrder = d.order;
      qs("m_orderId").textContent = modalOrder.orderId || "—"; qs("m_customer").textContent = modalOrder.customer?.fullName || "—"; qs("m_phone").textContent = modalOrder.customer?.phone || "—"; 
      qs("m_addr").textContent = (modalOrder.address?.streetAddress || "") + ", " + (modalOrder.address?.town || ""); qs("m_run").textContent = (modalOrder.runKey||""); qs("m_fees").textContent = "$" + money(modalOrder.pricingSnapshot?.totalFees || 0); qs("m_groceriesCurrent").textContent = modalOrder.payments?.groceries?.status || "—"; qs("m_state").value = (modalOrder.status?.state || "submitted"); qs("m_list").textContent = modalOrder.list?.groceryListText || "—"; qs("m_addons").textContent = buildAddonsText(modalOrder);
      qs("m_finalGroceryTotal").value = "";
      openModal(true);
    } catch(e){ toast(String(e)); }
  }

  qs("m_captureBtn").addEventListener("click", async () => {
    if(!modalOrder?.orderId) return;
    const finalGroc = qs("m_finalGroceryTotal").value;
    if(!finalGroc) return toast("Enter the exact grocery total from the receipt.");
    if(!confirm("Capture exact payment and dispatch driver?")) return;
    try {
      const r = await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/capture", {
        method: "POST", headers:{ "Content-Type":"application/json" }, credentials: "include",
        body: JSON.stringify({ finalGroceryTotal: Number(finalGroc) })
      });
      const d = await r.json();
      if(!r.ok || d.ok===false) throw new Error(d.error || "Capture failed");
      toast("Payment captured & customer notified! ✅");
      await openOrder(modalOrder.orderId); await search();
    } catch(e) { toast(String(e.message||e)); }
  });

  async function saveStatus(){ if(!modalOrder?.orderId) return; try{ await fetch("/api/admin/orders/" + encodeURIComponent(modalOrder.orderId) + "/status", { method:"POST", headers:{ "Content-Type":"application/json" }, credentials:"include", body: JSON.stringify({ state: qs("m_state").value }) }); toast("Status saved ✅"); await search(); } catch(e){ toast(String(e)); } }
  qs("closeModal").addEventListener("click", ()=> openModal(false)); qs("searchBtn").addEventListener("click", search); qs("clearBtn").addEventListener("click", ()=>{ qs("q").value=""; qs("runKey").value=""; search(); }); qs("m_saveState").addEventListener("click", saveStatus);
  search();
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