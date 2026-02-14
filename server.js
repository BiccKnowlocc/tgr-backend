require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const mongoose = require("mongoose");

const User = require("./models/User");

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
// NOTE: MemoryStore warning is OK for testing.
// Later we’ll swap to Mongo-backed session store (connect-mongo).
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

app.get("/", (req, res) => {
  if (req.user) return res.redirect("/member");
  res.type("html").send(`
    <h1>TGR Backend</h1>
    <p><a href="/auth/google">Login with Google</a></p>
    <p><a href="/health">Health Check</a></p>
    <p>BASE_URL: ${BASE_URL}</p>
  `);
});

// Start login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

// OAuth callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => res.redirect("/member")
);

// Logout
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("tgr.sid");
      res.redirect("/");
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

// ===== ORDER HISTORY: SAVE ORDER (AUTH REQUIRED) =====
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const p = req.body || {};

    const primaryStore = (p.primary_store || "").trim();
    const groceryList = (p.grocery_list || "").trim();

    if (!primaryStore) return res.status(400).json({ ok: false, error: "Missing primary_store" });
    if (!groceryList) return res.status(400).json({ ok: false, error: "Missing grocery_list" });

    const { runDate, payDeadline, listDeadline, followingRun } = computeNextRunDates();

    const order = {
      createdAt: new Date(),
      runDate,
      payDeadline,
      listDeadline,
      followingRun,
      primaryStore,
      secondaryStore: p.secondary_store || "",
      community: p.community || "",
      streetAddress: p.street_address || "",
      phone: p.phone || "",
      groceryList,
      notes: p.grocery_notes || "",
      status: "submitted",
      addOns: {
        fastFood: p.addon_fast_food === "yes" || p.addon_fast_food === true,
        liquor: p.addon_liquor === "yes" || p.addon_liquor === true,
        printing: p.addon_printing === "yes" || p.addon_printing === true,
        ride: p.addon_ride === "yes" || p.addon_ride === true,
      },
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

// ===== MEMBER PAGE (styled portal + auto run dates) =====
app.get("/member", (req, res) => {
  if (!req.user) return res.redirect("/");

  const u = req.user;
  const renewal = u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A";

  const perks = (u.perks && u.perks.length) ? u.perks : [
    "Priority booking on run days",
    "Reduced extra-store fees (based on tier)",
    "Faster issue resolution support",
  ];

  const discounts = (u.discounts && u.discounts.length) ? u.discounts : [
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

  const manageUrl = process.env.SQUARE_MANAGE_MEMBERSHIP_URL || "https://tobermorygroceryrun.ca/indexapp.html";
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
        <ul>${perks.map(p => `<li>${p}</li>`).join("")}</ul>
        <h3>Your Discounts</h3>
        <ul>${discounts.map(d => `<li>${d}</li>`).join("")}</ul>
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
        <a class="btn primary" href="https://tobermorygroceryrun.ca/indexapp.html" target="_blank" rel="noopener">Place an Order</a>
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

// ===== ADMIN (OPTIONAL) =====
function requireAdmin(req, res, next) {
  if (req.query.key && process.env.ADMIN_KEY && req.query.key === process.env.ADMIN_KEY) return next();
  return res.status(401).send("Unauthorized.");
}

app.get("/admin/users", requireAdmin, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).limit(200).lean();
  res.json(users);
});

app.get("/admin/set-membership", requireAdmin, async (req, res) => {
  const { email, level, status, renewal } = req.query;

  if (!email) return res.status(400).send("Missing email.");
  if (!level) return res.status(400).send("Missing level (none/member/runner/access).");
  if (!status) return res.status(400).send("Missing status (inactive/active/cancelled).");

  const update = {
    membershipLevel: level,
    membershipStatus: status,
    renewalDate: renewal ? new Date(renewal) : null,
  };

  const user = await User.findOneAndUpdate({ email: email.toLowerCase() }, update, { new: true });
  if (!user) return res.status(404).send("User not found.");

  res.send(`
    <h1>Updated ✅</h1>
    <p>${user.email}</p>
    <p>Status: ${user.membershipStatus}</p>
    <p>Level: ${user.membershipLevel}</p>
    <p>Renewal: ${user.renewalDate ? new Date(user.renewalDate).toLocaleDateString("en-CA") : "N/A"}</p>
  `);
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});