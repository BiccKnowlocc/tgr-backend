require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const mongoose = require("mongoose");

const User = require("./models/User");

// ===== Square SDK =====
const { SquareClient, SquareEnvironment } = require("square");

const SQUARE_ENV = (process.env.SQUARE_ENV || "sandbox").toLowerCase(); // "sandbox" or "production"

const square = new SquareClient({
  token: process.env.SQUARE_ACCESS_TOKEN,
  environment:
    SQUARE_ENV === "production"
      ? SquareEnvironment.Production
      : SquareEnvironment.Sandbox,
});

const SQUARE_LOCATION_ID = process.env.SQUARE_LOCATION_ID;

const app = express();

// ===== CONFIG =====
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

const ALLOWED_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
  "http://localhost:8888",
  "http://localhost:3000",
];

// Render/Proxies (required for secure cookies on Render)
app.set("trust proxy", 1);

// ===== MIDDLEWARE =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));

// Serve static assets if you keep any in the backend folder (optional)
app.use(express.static(__dirname));

// CORS for cross-site cookie auth (frontend -> backend)
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true); // curl/postman
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked origin: " + origin));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

// ===== DB =====
if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI in environment variables.");
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ===== SESSIONS =====
app.use(
  session({
    name: "tgr.sid", // IMPORTANT: set cookie name so logout clears the right one
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // Render is https
      sameSite: "none", // REQUIRED for cross-site cookies
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    },
  })
);

// ===== PASSPORT =====
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || null);
  } catch (e) {
    done(e);
  }
});

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: `${BASE_URL}/auth/google/callback`,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || "").toLowerCase();
        const photo = profile.photos?.[0]?.value || "";

        if (!email) return done(new Error("Google did not return an email address."));

        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            googleId: profile.id,
            email,
            name: profile.displayName || email,
            photo,
            membershipLevel: "none",
            membershipStatus: "inactive",
            renewalDate: null,
            discounts: [],
            perks: [],
            orderHistory: [],
          });
        } else {
          user.googleId = profile.id;
          user.name = profile.displayName || user.name;
          user.photo = photo || user.photo;
          await user.save();
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// ===== HELPERS =====
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, error: "Not logged in" });
}

// Admin list comes from Render env var: ADMIN_EMAILS="you@gmail.com,other@gmail.com"
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

function isAdminUser(req) {
  const email = (req.user?.email || "").toLowerCase();
  return ADMIN_EMAILS.includes(email);
}

// For API endpoints: return JSON
function requireAdminApi(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "Not logged in" });
  if (!isAdminUser(req)) return res.status(403).json({ ok: false, error: "Forbidden" });
  return next();
}

// For HTML pages: redirect to Google login then return to page
function requireAdminPage(req, res, next) {
  if (!req.user) {
    const returnTo = encodeURIComponent(req.originalUrl || "/admin");
    return res.redirect(`/auth/google?returnTo=${returnTo}`);
  }
  if (!isAdminUser(req)) return res.status(403).send("Forbidden");
  return next();
}

// ===== RUN DATE CALC =====
function computeNextRunDates() {
  const today = new Date();
  const day = today.getDay(); // 0=Sun
  const daysUntilSunday = ((7 - day) % 7) || 7; // next Sunday (not today)
  const runDate = new Date(today);
  runDate.setDate(today.getDate() + daysUntilSunday);

  const payDeadline = new Date(runDate);
  payDeadline.setDate(runDate.getDate() - 2); // Friday before

  const listDeadline = new Date(runDate);
  listDeadline.setDate(runDate.getDate() - 1); // Saturday before

  const followingRun = new Date(runDate);
  followingRun.setDate(runDate.getDate() + 14);

  return { runDate, payDeadline, listDeadline, followingRun };
}

// Fix common bad pasted path like /https://tgr-backend.onrender.com/...
app.get(/^\/https?:\/\/.*/i, (req, res) => res.redirect("/"));

// ===== ROUTES =====
app.get("/health", (req, res) => res.send("OK server is running"));

function safeReturnToPath(p) {
  // Allow only local paths like "/admin" or "/member"
  if (!p || typeof p !== "string") return "/member";
  if (!p.startsWith("/")) return "/member";
  // Optional: restrict to only these:
  const allowed = ["/member", "/admin", "/admin/order"];
  if (!allowed.includes(p.split("?")[0])) return "/member";
  return p;
}

app.get(
  "/auth/google",
  (req, res, next) => {
    const returnTo = safeReturnToPath(req.query.returnTo || "/member");

    // Put returnTo into "state" so we don't rely on sessions surviving OAuth redirect
    const state = Buffer.from(JSON.stringify({ returnTo }), "utf8").toString("base64url");

    console.log("LOGIN START returnTo =", returnTo, "state =", state);

    // stash it on req for passport options
    req._oauthState = state;
    next();
  },
  (req, res, next) => {
    passport.authenticate("google", {
      scope: ["profile", "email"],
      prompt: "select_account",
      state: req._oauthState,
    })(req, res, next);
  }
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    let returnTo = "/member";

    try {
      if (req.query.state) {
        const decoded = JSON.parse(Buffer.from(String(req.query.state), "base64url").toString("utf8"));
        returnTo = safeReturnToPath(decoded.returnTo);
      }
    } catch {}

    console.log("CALLBACK state returnTo =", returnTo);
    return res.redirect(returnTo);
  }
);// Logout (defaults back to homepage)
app.get("/logout", (req, res) => {
  const fallback = "https://tobermorygroceryrun.ca/";
  const returnToRaw = req.query.returnTo || fallback;

  let returnTo = fallback;
  try {
    const u = new URL(returnToRaw);
    const host = u.hostname.toLowerCase();
    const allowed = ["tobermorygroceryrun.ca", "www.tobermorygroceryrun.ca"];
    if (allowed.includes(host)) returnTo = u.toString();
  } catch {
    // keep fallback
  }

  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("tgr.sid");
      res.redirect(returnTo);
    });
  });
});

// Who am I (for frontend checks)
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ ok: true, loggedIn: false });
  return res.json({
    ok: true,
    loggedIn: true,
    user: {
      email: req.user.email,
      name: req.user.name,
      photo: req.user.photo || "",
      membershipLevel: req.user.membershipLevel || "none",
      membershipStatus: req.user.membershipStatus || "inactive",
      renewalDate: req.user.renewalDate,
    },
  });
});

// =========================
// ADMIN HTML PAGES
// Paste this AFTER /api/me
// Requires: requireAdminPage (and ADMIN_EMAILS/isAdminUser helpers) already defined above.
// =========================

app.get("/admin", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Orders</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    table{width:100%;border-collapse:collapse;}
    th,td{border-bottom:1px solid #ddd;padding:8px;text-align:left;font-size:14px;vertical-align:top;}
    th{background:#f5f5f5;}
    a{font-weight:700;}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px;}
    .muted{opacity:.75;font-weight:500;}
    .pill{display:inline-block;padding:3px 10px;border:1px solid #ddd;border-radius:999px;font-size:12px;}
  </style>
</head>
<body>
  <div class="top">
    <h2 style="margin:0;">Admin Orders</h2>
    <a href="/member">Member</a>
    <a href="/admin/picklist">Picklist</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
    <span class="pill">Signed in as: ${(req.user?.email || "")}</span>
  </div>

  <div id="out">Loading…</div>

 <script>
  async function load(){
    const out = document.getElementById("out");

    let r, data;
    try {
      r = await fetch("/api/admin/orders", { credentials: "include" });
      data = await r.json();
    } catch (e) {
      out.textContent = "Failed to load orders: " + String(e);
      return;
    }

    if (!r.ok || data.ok === false) {
      out.textContent = (data && data.error) ? data.error : ("Error loading orders (" + r.status + ")");
      return;
    }

    const orders = data.orders || [];
    let rows = "";

    for (const o of orders) {
      const viewUrl =
        "/admin/order?userId=" + encodeURIComponent(String(o.userId)) +
        "&orderId=" + encodeURIComponent(String(o.orderId));

      const created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";
      rows +=
        "<tr>" +
          "<td>" + created + "</td>" +
          "<td>" + (o.userName || "") + "</td>" +
          "<td>" + (o.userEmail || "") + "</td>" +
          "<td>" + (o.community || "") + "</td>" +
          "<td>" + (o.primaryStore || "") + "</td>" +
          "<td>" + (o.status || "") + "</td>" +
          "<td><a href='" + viewUrl + "'>View</a></td>" +
        "</tr>";
    }

    out.innerHTML =
      "<table>" +
        "<thead>" +
          "<tr>" +
            "<th>Created</th><th>Name</th><th>Email</th><th>Community</th><th>Store</th><th>Status</th><th></th>" +
          "</tr>" +
        "</thead>" +
        "<tbody>" +
          (rows || "<tr><td colspan='7' style='opacity:.75'>No orders found.</td></tr>") +
        "</tbody>" +
      "</table>";
  }

  load();
</script>
</body>
</html>`);
});

app.get("/admin/order", requireAdminPage, (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Order</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    pre{white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;}
    a{font-weight:700;}
  </style>
</head>
<body>
  <a href="/admin">← Back to all orders</a>
  <h2>Order Detail</h2>
  <div id="out">Loading…</div>

 <script>
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
    }[c]));
  }

  async function fetchTextWithTimeout(url, ms) {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), ms);
    try {
      const r = await fetch(url, { credentials: "include", signal: c.signal });
      const text = await r.text();
      return { r, text };
    } finally {
      clearTimeout(t);
    }
  }

  async function load(){
    const out = document.getElementById("out");
    out.textContent = "Loading…";

    const params = new URLSearchParams(location.search);
    const userId = params.get("userId");
    const orderId = params.get("orderId");

    if (!userId || !orderId) {
      out.textContent = "Missing userId or orderId in URL.";
      return;
    }

    const url = "/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId);

    let r, text;
    try {
      ({ r, text } = await fetchTextWithTimeout(url, 10000));
    } catch (e) {
      out.textContent = "Fetch failed (timeout/network): " + String(e);
      return;
    }

    if (!r.ok) {
      out.innerHTML =
        "<h3>API error " + r.status + "</h3>" +
        "<pre style='white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;'>" +
        esc(text.slice(0, 2000)) +
        "</pre>";
      return;
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      out.innerHTML =
        "<h3>Expected JSON but got:</h3>" +
        "<pre style='white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;'>" +
        esc(text.slice(0, 2000)) +
        "</pre>";
      return;
    }

    if (data.ok === false) {
      out.textContent = data.error || "Error";
      return;
    }

    const o = data.order || {};
    const add = o.addOns || {};
    const addOnsText = [
      add.fastFood ? "Fast Food" : null,
      add.liquor ? "Liquor" : null,
      add.printing ? "Printing" : null,
      add.ride ? "Ride" : null,
    ].filter(Boolean).join(", ") || "None";

    const html =
      '<div style="margin:8px 0;opacity:.75">' +
        '<div><strong>' + esc((data.user && data.user.name) ? data.user.name : "") + '</strong> (' + esc((data.user && data.user.email) ? data.user.email : "") + ')</div>' +
        '<div>Submitted: ' + (o.createdAt ? esc(new Date(o.createdAt).toLocaleString()) : "") + '</div>' +
        '<div>Run Date: ' + (o.runDate ? esc(new Date(o.runDate).toLocaleDateString()) : "") + '</div>' +
      '</div>' +

      '<h3>Stores</h3>' +
      '<div><strong>Primary:</strong> ' + esc(o.primaryStore || "") + '</div>' +
      '<div><strong>Secondary:</strong> ' + esc(o.secondaryStore || "") + '</div>' +

      '<h3>Add-ons</h3>' +
      '<div>' + esc(addOnsText) + '</div>' +

      '<h3>Delivery</h3>' +
      '<div><strong>Community:</strong> ' + esc(o.community || "") + '</div>' +
      '<div><strong>Address:</strong> ' + esc(o.streetAddress || "") + '</div>' +
      '<div><strong>Phone:</strong> ' + esc(o.phone || "") + '</div>' +

      '<h3>Grocery List</h3>' +
      '<pre style="white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;">' +
        esc(o.groceryList || "") +
      '</pre>' +

      '<h3>Drop-off / Notes</h3>' +
      '<pre style="white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;">' +
        esc(o.notes || "") +
      '</pre>';

    out.innerHTML = html;
  }

  load();
</script>
</body>
</html>
  `);
});
// A simpler “picklist” page: just stores + grocery list + notes (easy to scan)
app.get("/admin/picklist", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Picklist</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px;}
    .card{border:1px solid #ddd;border-radius:10px;padding:10px;margin:10px 0;}
    .muted{opacity:.75}
    .hdr{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap}
  </style>
</head>
<body>
  <div class="top">
    <h2 style="margin:0;">Picklist</h2>
    <a href="/admin">All Orders</a>
    <a href="/member">Member</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
  </div>

  <div id="out">Loading…</div>

  <script>
    async function load(){
      const r = await fetch("/api/admin/orders", { credentials:"include" });
      const data = await r.json().catch(()=>({}));
      if(!r.ok || data.ok===false){
        document.getElementById("out").textContent = data.error || "Error loading orders";
        return;
      }

     // For picklist we need FULL details, so we fetch each order detail.
      const orders = data.orders || [];
      const out = document.getElementById("out");

      function esc(s){
        return String(s ?? "").replace(/[&<>"']/g, (c) => ({
          "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"
        }[c]));
      }

      function pickField(ord, camel, snake){
        const a = ord && ord[camel];
        if (a !== undefined && a !== null && String(a).trim() !== "") return a;
        const b = ord && ord[snake];
        if (b !== undefined && b !== null && String(b).trim() !== "") return b;
        return "";
      }

      async function fetchWithTimeout(url, ms = 8000){
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), ms);
        try {
          const r = await fetch(url, { credentials:"include", signal: controller.signal });
          return r;
        } finally {
          clearTimeout(t);
        }
      }

      const chunks = [];

      for (const o of orders) {
        const url = "/api/admin/orders/" + encodeURIComponent(String(o.userId)) + "/" + encodeURIComponent(String(o.orderId));

        let rr, dd;
        try {
          rr = await fetchWithTimeout(url, 8000);
          dd = await rr.json().catch(()=>({}));
        } catch (e) {
          continue;
        }
        if(!rr.ok || dd.ok===false) continue;

        const ord = dd.order || {};

        // Normalize old/new field names
        const primaryStore   = pickField(ord, "primaryStore", "primary_store");
        const secondaryStore = pickField(ord, "secondaryStore", "secondary_store");
        const groceryList    = pickField(ord, "groceryList", "grocery_list");
        const community      = pickField(ord, "community", "community");
        const streetAddress  = pickField(ord, "streetAddress", "street_address");
        const phone          = pickField(ord, "phone", "phone");
        const notes          = pickField(ord, "notes", "grocery_notes");

        const add = ord.addOns || ord.addons || {};
        const addOnsText = [
          add.fastFood ? "Fast Food" : null,
          add.liquor ? "Liquor" : null,
          add.printing ? "Printing" : null,
          add.ride ? "Ride" : null,
        ].filter(Boolean).join(", ") || "None";

 chunks.push(
          "<div class='card'>" +
            "<div class='hdr'>" +
              "<div><strong>" + esc(dd.user?.name || "") + "</strong> <span class='muted'>(" + esc(dd.user?.email || "") + ")</span></div>" +
              "<div class='muted'>" + (ord.createdAt ? esc(new Date(ord.createdAt).toLocaleString()) : "") + "</div>" +
            "</div>" +

            "<div><strong>Primary store:</strong> " + esc(primaryStore) + "</div>" +
            "<div><strong>Secondary store:</strong> " + esc(secondaryStore) + "</div>" +

            "<div><strong>Community:</strong> " + esc(community) + "</div>" +
            "<div><strong>Address:</strong> " + esc(streetAddress) + "</div>" +
            "<div><strong>Phone:</strong> " + esc(phone) + "</div>" +

            "<div style='margin-top:8px'><strong>Add-ons:</strong> " + esc(addOnsText) + "</div>" +

            "<div style='margin-top:8px'><strong>Grocery list:</strong></div>" +
            "<pre class='mono'>" + esc(groceryList) + "</pre>" +

            (notes
              ? "<div style='margin-top:8px'><strong>Drop-off / Notes:</strong></div><pre class='mono'>" + esc(notes) + "</pre>"
              : ""
            ) +
          "</div>"
        );

      out.innerHTML = chunks.join("") || "<div class='muted'>No orders found.</div>";
    }
    load();
  </script>
</body>
</html>`);
});



// ===== ORDER HISTORY: SAVE ORDER (AUTH REQUIRED) =====
app.post("/api/orders", requireAuth, async (req, res) => {
 try {
    const p = req.body || {};

    // Accept both snake_case (old) and camelCase (new)
    const primaryStore = String(p.primary_store ?? p.primaryStore ?? "").trim();
    const secondaryStore = String(p.secondary_store ?? p.secondaryStore ?? "").trim();

    const groceryList = String(p.grocery_list ?? p.groceryList ?? "").trim();

    const community = String(p.community ?? "").trim();
    const streetAddress = String(p.street_address ?? p.streetAddress ?? "").trim();
    const phone = String(p.phone ?? "").trim();

    const notes = String(p.grocery_notes ?? p.notes ?? p.dropoff_notes ?? p.dropoffNotes ?? "").trim();

    // Add-ons: accept multiple keys
    const addOns = {
      fastFood: (p.addon_fast_food ?? p.addOnFastFood ?? p.fastFood) === "yes" || (p.addon_fast_food ?? p.addOnFastFood ?? p.fastFood) === true,
      liquor: (p.addon_liquor ?? p.addOnLiquor ?? p.liquor) === "yes" || (p.addon_liquor ?? p.addOnLiquor ?? p.liquor) === true,
      printing: (p.addon_printing ?? p.addOnPrinting ?? p.printing) === "yes" || (p.addon_printing ?? p.addOnPrinting ?? p.printing) === true,
      ride: (p.addon_ride ?? p.addOnRide ?? p.ride) === "yes" || (p.addon_ride ?? p.addOnRide ?? p.ride) === true,
    };

    if (!primaryStore) return res.status(400).json({ ok: false, error: "Missing primary store" });
    if (!groceryList) return res.status(400).json({ ok: false, error: "Missing grocery list" });

    const { runDate, payDeadline, listDeadline, followingRun } = computeNextRunDates();

    const order = {
      createdAt: new Date(),
      runDate,
      payDeadline,
      listDeadline,
      followingRun,
      primaryStore,
      secondaryStore,
      community,
      streetAddress,
      phone,
      groceryList,
      notes,      // includes drop-off notes if your frontend sends that
      status: "submitted",
      addOns,
    };




    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    user.orderHistory = user.orderHistory || [];
    user.orderHistory.unshift(order);
    await user.save();

    return res.json({ ok: true, order });
  } catch (e) {
    console.error("POST /api/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Read order history for logged-in user
app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).lean();
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });
    return res.json({ ok: true, orders: user.orderHistory || [] });
  } catch (e) {
    console.error("GET /api/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ===== ADMIN API: ALL ORDERS (ACROSS ALL USERS) =====
app.get("/api/admin/orders", requireAdminApi, async (req, res) => {
  try {
    const users = await User.find({}, { email: 1, name: 1, orderHistory: 1 }).lean();

    const orders = [];
    for (const u of users) {
      for (const o of u.orderHistory || []) {
        orders.push({
  userId: u._id,
  userEmail: u.email,
  userName: u.name,

  orderId: o._id,
  createdAt: o.createdAt,
  runDate: o.runDate,

  community: o.community,
  streetAddress: o.streetAddress,
  phone: o.phone,

  primaryStore: o.primaryStore,
  secondaryStore: o.secondaryStore,

  status: o.status,

  // include these so admin can show them without opening detail
  notes: o.notes,
  addOns: o.addOns || {},
});
      }
    }

    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return res.json({ ok: true, orders });
  } catch (e) {
    console.error("GET /api/admin/orders error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});



// ===== ADMIN API: SINGLE ORDER DETAIL =====
app.get("/api/admin/orders/:userId/:orderId", requireAdminApi, async (req, res) => {
  try {
    const { userId, orderId } = req.params;

    const user = await User.findById(userId).lean();
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const order = (user.orderHistory || []).find((o) => String(o._id) === String(orderId));
    if (!order) return res.status(404).json({ ok: false, error: "Order not found" });

    return res.json({
      ok: true,
      user: { id: user._id, email: user.email, name: user.name },
      order,
    });
  } catch (e) {
    console.error("GET /api/admin/orders/:userId/:orderId error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ===== MEMBER PAGE (styled portal + auto run dates) =====
app.get("/member", (req, res) => {
  if (!req.user) return res.redirect("/");

  const u = req.user;
  const renewal = u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A";

  const perks = u.perks && u.perks.length ? u.perks : [
    "Priority booking on run days",
    "Reduced extra-store fees (based on tier)",
    "Faster issue resolution support",
  ];

  const discounts = u.discounts && u.discounts.length ? u.discounts : [
    "Member discounts apply to service/delivery fees (where applicable)",
  ];

  const orderRows = (u.orderHistory || [])
    .slice()
    .reverse()
    .map((o) => {
      const created = o.createdAt ? new Date(o.createdAt).toLocaleDateString("en-CA") : "";
      const run = o.runDate ? new Date(o.runDate).toLocaleDateString("en-CA") : "—";
      const store = o.primaryStore || "—";
      const status = o.status || "submitted";
      return `
        <tr>
          <td>${created}</td>
          <td>${run}</td>
          <td>${store}</td>
          <td><span class="badge">${status}</span></td>
        </tr>`;
    })
    .join("");

  const manageUrl =
    process.env.SQUARE_MANAGE_MEMBERSHIP_URL || "https://tobermorygroceryrun.ca/indexapp.html";
  const cancelUrl =
    process.env.SQUARE_CANCEL_MEMBERSHIP_URL ||
    "mailto:members@tobermorygroceryrun.ca?subject=Membership%20Cancellation%20Request";

  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>TGR Member Portal</title>
<style>
  :root{
    --bg:#0f1526; --card:#121a2e; --text:#ffffff;
    --muted:rgba(255,255,255,.75); --line:rgba(255,255,255,.14);
    --brand:#1f2a44; --accent:#e3342f; --soft:rgba(227,52,47,.12);
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.55}
  header{background:var(--brand);border-bottom:1px solid var(--line);padding:14px 14px}
  .wrap{max-width:980px;margin:0 auto;padding:0 14px}
  .hdr{display:flex;align-items:center;gap:12px}
  .logo{width:86px;height:auto;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.06);padding:6px}
  h1{margin:0;font-size:1.25rem}
  .sub{margin:2px 0 0;color:var(--muted);font-size:.95rem}
  main{max-width:980px;margin:0 auto;padding:14px 14px 40px}
  .grid{display:grid;grid-template-columns:1.3fr .7fr;gap:12px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;box-shadow:0 12px 40px rgba(0,0,0,.35)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid var(--line);font-size:.85rem;color:var(--muted)}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.07);border:1px solid var(--line);font-size:.82rem}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 14px;border-radius:999px;
    border:1px solid rgba(255,255,255,.18);text-decoration:none;color:var(--text);font-weight:800}
  .btn.primary{background:var(--accent);border-color:rgba(0,0,0,.15)}
  .btn.ghost{background:transparent}
  .muted{color:var(--muted)}
  .tabs{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0}
  .tab{border:1px solid var(--line);background:rgba(255,255,255,.06);color:var(--text);padding:8px 12px;border-radius:999px;
    cursor:pointer;font-weight:800}
  .tab[aria-selected="true"]{background:var(--soft);border-color:rgba(227,52,47,.5)}
  .panel{display:none;margin-top:12px}
  .panel.active{display:block}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;font-size:.95rem}
  th{color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.06em}
  .run-info > div{margin:6px 0}
  hr{border:none;border-top:1px solid var(--line);margin:14px 0}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div class="hdr">
      <img src="/tgr_logo_tight_512.png" class="logo" alt="TGR logo" />
      <div>
        <h1>Member Portal</h1>
        <div class="sub">Signed in as ${u.email}</div>
      </div>
    </div>
  </div>
</header>

<main>
  <div class="grid">
    <section class="card">
      <div class="row" style="justify-content:space-between">
        <div class="row" style="gap:8px">
          <div class="pill">Name: <strong>${u.name || ""}</strong></div>
          <div class="pill">Status: <strong>${u.membershipStatus || "inactive"}</strong></div>
          <div class="pill">Level: <strong>${u.membershipLevel || "none"}</strong></div>
          <div class="pill">Renewal: <strong>${renewal}</strong></div>
        </div>
        <div class="row">
          <a class="btn ghost" href="/logout">Log out</a>
        </div>
      </div>

      <div class="tabs" role="tablist">
        <button class="tab" id="tab-membership" aria-selected="true" type="button">Membership</button>
        <button class="tab" id="tab-perks" aria-selected="false" type="button">Perks & Discounts</button>
        <button class="tab" id="tab-orders" aria-selected="false" type="button">Order History</button>
      </div>

      <div id="panel-membership" class="panel active">
        <p class="muted">Manage billing or request cancellation.</p>
        <div class="row">
          <a class="btn primary" href="${manageUrl}" target="_blank" rel="noopener">Manage / Pay Membership</a>
          <a class="btn ghost" href="${cancelUrl}" target="_blank" rel="noopener">Cancel / Request Cancellation</a>
        </div>
      </div>

      <div id="panel-perks" class="panel">
        <h3>Your Perks</h3>
        <ul>${perks.map((p) => `<li>${p}</li>`).join("")}</ul>
        <h3>Your Discounts</h3>
        <ul>${discounts.map((d) => `<li>${d}</li>`).join("")}</ul>
      </div>

      <div id="panel-orders" class="panel">
        <h3>Order History</h3>
        <table>
          <thead><tr><th>Submitted</th><th>Run Date</th><th>Store</th><th>Status</th></tr></thead>
          <tbody>
            ${orderRows || `<tr><td colspan="4" class="muted">No orders on file yet.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>

    <aside class="card">
      <h3>Upcoming Runs</h3>
      <div class="run-info">
        <div><span class="muted">Next delivery Sunday:</span> <strong id="mp-next-run">Calculating…</strong></div>
        <div><span class="muted">Payment deadline (Friday):</span> <strong><span id="mp-pay-deadline">Calculating…</span> 6:00 pm</strong></div>
        <div><span class="muted">List deadline (Saturday):</span> <strong><span id="mp-list-deadline">Calculating…</span> 6:00 pm</strong></div>
        <div><span class="muted">Following run (+2 weeks):</span> <strong id="mp-following-run">Calculating…</strong></div>
      </div>

      <hr />

      <h3>Quick Links</h3>
      <div class="row" style="flex-direction:column;align-items:stretch">
        <a class="btn primary" href="https://tobermorygroceryrun.ca/?tab=order" target="_blank" rel="noopener">Place an Order</a>
        <a class="btn ghost" href="https://tobermorygroceryrun.ca/" target="_blank" rel="noopener">Open Main App</a>
        <a class="btn ghost" href="https://tobermorygroceryrun.ca/terms.html" target="_blank" rel="noopener">Terms & Conditions</a>
        <a class="btn ghost" href="mailto:orders@tobermorygroceryrun.ca">Email Orders</a>
        <a class="btn ghost" href="mailto:members@tobermorygroceryrun.ca">Email Membership</a>
      </div>
    </aside>
  </div>
</main>

<script>
  const tabs = [
    { tab: "tab-membership", panel: "panel-membership" },
    { tab: "tab-perks", panel: "panel-perks" },
    { tab: "tab-orders", panel: "panel-orders" },
  ];

  function selectTab(tabId){
    tabs.forEach(({tab, panel}) => {
      const t = document.getElementById(tab);
      const p = document.getElementById(panel);
      const active = (tab === tabId);
      t.setAttribute("aria-selected", active ? "true" : "false");
      p.classList.toggle("active", active);
    });
  }

  tabs.forEach(({tab}) => {
    document.getElementById(tab).addEventListener("click", () => selectTab(tab));
  });

  function fmt(d){
    return d.toLocaleDateString("en-CA", { year:"numeric", month:"short", day:"numeric" });
  }

  function computeNextRunInfo(){
    const today = new Date();
    const day = today.getDay();
    const daysUntilSunday = ((7 - day) % 7) || 7;
    const runDate = new Date(today);
    runDate.setDate(today.getDate() + daysUntilSunday);

    const payDeadline = new Date(runDate);
    payDeadline.setDate(runDate.getDate() - 2);

    const listDeadline = new Date(runDate);
    listDeadline.setDate(runDate.getDate() - 1);

    const followingRun = new Date(runDate);
    followingRun.setDate(runDate.getDate() + 14);

    return {
      runLabel: fmt(runDate),
      payDeadlineLabel: fmt(payDeadline),
      listDeadlineLabel: fmt(listDeadline),
      followingRunLabel: fmt(followingRun)
    };
  }

  function updateRunUI(){
    const info = computeNextRunInfo();
    const a = document.getElementById("mp-next-run");
    const b = document.getElementById("mp-pay-deadline");
    const c = document.getElementById("mp-list-deadline");
    const d = document.getElementById("mp-following-run");

    if (a) a.textContent = info.runLabel;
    if (b) b.textContent = info.payDeadlineLabel;
    if (c) c.textContent = info.listDeadlineLabel;
    if (d) d.textContent = info.followingRunLabel;
  }

  document.addEventListener("DOMContentLoaded", () => {
    updateRunUI();
    setInterval(updateRunUI, 60 * 60 * 1000);
  });
</script>
</body>
</html>`);
});

// ===== ADMIN HTML PAGES =====
app.get("/admin", requireAdminPage, (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Orders</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    table{width:100%;border-collapse:collapse;}
    th,td{border-bottom:1px solid #ddd;padding:8px;text-align:left;font-size:14px;}
    th{background:#f5f5f5;}
    a{font-weight:700;}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px;}
    .muted{opacity:.75;font-weight:500;}
  </style>
</head>
<body>
  <div class="top">
    <h2 style="margin:0;">Admin Orders</h2>
    <a href="/member">Member</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
    <span class="muted">Signed in as: ${(req.user.email || "")}</span>
  </div>

  <div id="out">Loading…</div>

  <script>
    async function load(){
      const r = await fetch("/api/admin/orders", { credentials:"include" });
      const data = await r.json().catch(()=>({}));
      if(!r.ok || data.ok===false){
        document.getElementById("out").textContent = data.error || "Error loading orders";
        return;
      }
     const orders = data.orders || [];
let rows = "";

for (const o of orders) {
  const viewUrl =
    "/admin/order?userId=" + encodeURIComponent(String(o.userId)) +
    "&orderId=" + encodeURIComponent(String(o.orderId));

  const created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";

  rows +=
    "<tr>" +
      "<td>" + created + "</td>" +
      "<td>" + (o.userName || "") + "</td>" +
      "<td>" + (o.userEmail || "") + "</td>" +
      "<td>" + (o.community || "") + "</td>" +
      "<td>" + (o.primaryStore || "") + "</td>" +
      "<td>" + (o.status || "") + "</td>" +
      "<td><a href='" + viewUrl + "'>View</a></td>" +
    "</tr>";
}

out.innerHTML =
  "<table>" +
    "<thead><tr>" +
      "<th>Created</th><th>Name</th><th>Email</th><th>Community</th><th>Store</th><th>Status</th><th></th>" +
    "</tr></thead>" +
    "<tbody>" +
      (rows || "<tr><td colspan='7' style='opacity:.75'>No orders found.</td></tr>") +
    "</tbody>" +
  "</table>";
          <thead>
            <tr>
              <th>Created</th><th>Name</th><th>Email</th><th>Community</th><th>Store</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>\${rows || '<tr><td colspan="7" class="muted">No orders found.</td></tr>'}</tbody>
        </table>\`;
    }
    load();
  </script>
</body>
</html>
  `);
});

app.get("/admin/order", requireAdminPage, (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Order Detail</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    a{font-weight:700;}
    .muted{opacity:.75}
    pre{white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;}
    .row{margin:6px 0}
    .pill{display:inline-block;padding:3px 10px;border:1px solid #ddd;border-radius:999px;font-size:12px;margin-right:6px}
  </style>
</head>
<body>
  <a href="/admin">← Back to all orders</a>
  <h2>Order Detail</h2>
  <div id="out">Loading…</div>

  <script>
 function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&":"&amp;",
    "<":"&lt;",
    ">":"&gt;",
    "\"":"&quot;",
    "'":"&#39;"
  }[c]));
}

    async function load(){
      const out = document.getElementById("out");

      const params = new URLSearchParams(location.search);
      const userId = params.get("userId");
      const orderId = params.get("orderId");

      if (!userId || !orderId) {
        out.textContent = "Missing userId or orderId in the URL.";
        return;
      }

      const url = "/api/admin/orders/" + encodeURIComponent(userId) + "/" + encodeURIComponent(orderId);

      let r, text;
      try {
        r = await fetch(url, { credentials: "include" });
        text = await r.text();
      } catch (e) {
        out.textContent = "Network error calling admin API: " + String(e);
        return;
      }

      if (!r.ok) {
        out.textContent = "API error " + r.status + ":\\n\\n" + text.slice(0, 800);
        return;
      }

      let data;
      try {
        data = JSON.parse(text);
      } catch {
        out.textContent = "Expected JSON, got:\\n\\n" + text.slice(0, 800);
        return;
      }

      if (data.ok === false) {
        out.textContent = data.error || "Unknown error";
        return;
      }

      const o = data.order || {};

      const add = o.addOns || {};
      const addOnsText = [
        add.fastFood ? "Fast Food" : null,
        add.liquor ? "Liquor" : null,
        add.printing ? "Printing" : null,
        add.ride ? "Ride" : null,
      ].filter(Boolean).join(", ") || "None";

      const created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";
      const runDate = o.runDate ? new Date(o.runDate).toLocaleDateString() : "";

      out.innerHTML =
        "<div class='muted row'><span class='pill'>Submitted: " + esc(created) + "</span><span class='pill'>Run: " + esc(runDate) + "</span></div>" +
        "<h3>" + esc((data.user && data.user.name) ? data.user.name : "") + " (" + esc((data.user && data.user.email) ? data.user.email : "") + ")</h3>" +

        "<div class='row'><strong>Primary store:</strong> " + esc(o.primaryStore) + "</div>" +
        "<div class='row'><strong>Secondary store:</strong> " + esc(o.secondaryStore) + "</div>" +

        "<div class='row'><strong>Community:</strong> " + esc(o.community) + "</div>" +
        "<div class='row'><strong>Address:</strong> " + esc(o.streetAddress) + "</div>" +
        "<div class='row'><strong>Phone:</strong> " + esc(o.phone) + "</div>" +

        "<div class='row'><strong>Add-ons:</strong> " + esc(addOnsText) + "</div>" +

        "<h3>Grocery list</h3>" +
        "<pre>" + esc(o.groceryList) + "</pre>" +

        "<h3>Drop-off / Notes</h3>" +
        "<pre>" + esc(o.notes) + "</pre>";
    }

    load();
  </script>
</body>
</html>`);



});// ===== ADMIN UTIL ROUTES (optional, email-based auth) =====
app.get("/admin/users", requireAdminPage, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).limit(200).lean();
  res.json(users);
});

app.get("/admin/set-membership", requireAdminPage, async (req, res) => {
  const { email, level, status, renewal } = req.query;

  if (!email) return res.status(400).send("Missing email.");
  if (!level) return res.status(400).send("Missing level (none/member/runner/access).");
  if (!status) return res.status(400).send("Missing status (inactive/active/cancelled).");

  const update = {
    membershipLevel: level,
    membershipStatus: status,
    renewalDate: renewal ? new Date(renewal) : null,
  };

  const user = await User.findOneAndUpdate(
    { email: email.toLowerCase() },
    update,
    { new: true }
  );
  if (!user) return res.status(404).send("User not found.");

 res.send(`
    <h1>Updated ✅</h1>
    <p>${user.email}</p>
    <p>Status: ${user.membershipStatus}</p>
    <p>Level: ${user.membershipLevel}</p>
    <p>Renewal: ${
      user.renewalDate
        ? new Date(user.renewalDate).toLocaleDateString("en-CA")
        : "N/A"
    }</p>
  `);
});
 

app.get("/admin/packing", requireAdminPage, (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TGR Admin – Packing List</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:16px;}
    .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;}
    .card{border:1px solid #ddd;border-radius:10px;padding:12px;margin:10px 0;}
    pre{white-space:pre-wrap;background:#f6f6f6;border:1px solid #ddd;padding:10px;border-radius:8px;}
    .muted{opacity:.75}
  </style>
</head>
<body>
  <div class="top">
    <h2 style="margin:0;">Packing List</h2>
    <a href="/admin">All Orders</a>
    <a href="/logout?returnTo=https%3A%2F%2Ftobermorygroceryrun.ca%2F">Logout</a>
  </div>

  <div id="out">Loading…</div>

  <script>
    async function load(){
      const r = await fetch("/api/admin/orders", { credentials:"include" });
      const data = await r.json().catch(()=>({}));
      if(!r.ok || data.ok===false){
        document.getElementById("out").textContent = data.error || "Error loading orders";
        return;
      }

      const list = (data.orders || []);
      if(!list.length){
        document.getElementById("out").textContent = "No orders found.";
        return;
      }

      document.getElementById("out").innerHTML = (list || []).map(function (o) {
  // add-ons text (handle both old & new shapes)
  var ao = o.addOns || {};
  var addOnsText = [
    (ao.fastFood ? "Fast Food" : ""),
    (ao.liquor ? "Liquor" : ""),
    (ao.printing ? "Printing" : ""),
    (ao.ride ? "Ride" : "")
  ].filter(Boolean).join(", ");
  if (!addOnsText) addOnsText = "None";

  var created = o.createdAt ? new Date(o.createdAt).toLocaleString() : "";
  var run = o.runDate ? new Date(o.runDate).toLocaleDateString() : "";

  var viewHref =
    "/admin/order?userId=" + encodeURIComponent(String(o.userId || "")) +
    "&orderId=" + encodeURIComponent(String(o.orderId || ""));

  return (
    "<div class='card'>" +
      "<div class='muted'>" + safe(created) + " • Run: <strong>" + safe(run) + "</strong></div>" +
      "<div><strong>" + safe(o.userName || "") + "</strong> — " + safe(o.community || "") + "</div>" +

      "<div style='margin-top:8px;'>" +
        "<div><strong>Primary:</strong> " + safe(o.primaryStore || "") + "</div>" +
        "<div><strong>Secondary:</strong> " + safe(o.secondaryStore || "") + "</div>" +
      "</div>" +

      "<div style='margin-top:8px;'>" +
        "<div><strong>Address:</strong> " + safe(o.streetAddress || "") + "</div>" +
        "<div><strong>Phone:</strong> " + safe(o.phone || "") + "</div>" +
      "</div>" +

      "<div style='margin-top:8px;'><strong>Add-ons:</strong> " + safe(addOnsText) + "</div>" +

      "<h4 style='margin:12px 0 6px;'>Grocery List</h4>" +
      "<pre>" + safe(o.groceryList || "") + "</pre>" +

      "<h4 style='margin:12px 0 6px;'>Drop-off / Notes</h4>" +
      "<pre>" + safe(o.notes || "") + "</pre>" +

      "<div style='margin-top:10px;'>" +
        "<a href='" + viewHref + "'>View full order →</a>" +
      "</div>" +
    "</div>"
  );
}).join("");
    }
    load();
  </script>
</body>
</html>
  `);
});


// ===== ADMIN: PACKING LIST (FULL ORDER FIELDS) =====
app.get("/api/admin/orders/full", requireAdminApi, async (req, res) => {
  try {
    const users = await User.find({}, { email: 1, name: 1, orderHistory: 1 }).lean();

    const orders = [];
    for (const u of users) {
      for (const o of (u.orderHistory || [])) {
        orders.push({
          userId: u._id,
          userEmail: u.email,
          userName: u.name,
          orderId: o._id,

          createdAt: o.createdAt,
          runDate: o.runDate,

          community: o.community,
          streetAddress: o.streetAddress,
          phone: o.phone,

          primaryStore: o.primaryStore,
          secondaryStore: o.secondaryStore,

          groceryList: o.groceryList,
          notes: o.notes,

          addOns: o.addOns || {},
          status: o.status,
        });
      }
    }

    orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return res.json({ ok: true, orders });
  } catch (e) {
    console.error("GET /api/admin/orders/full error:", e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});


// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});