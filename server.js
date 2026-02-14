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
const FRONTEND_ORIGINS = [
  "https://tobermorygroceryrun.ca",
  "https://www.tobermorygroceryrun.ca",
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
    origin: FRONTEND_ORIGINS,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
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
    name: "tgr.sid",
    secret: process.env.SESSION_SECRET || "CHANGE_ME_IN_RENDER",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,      // Render is HTTPS
      sameSite: "none",  // allow cross-site cookie from your Netlify domain
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
  (req, res) => {
    // After login, go to member portal
    res.redirect("/member");
  }
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

// Save order into logged-in user's orderHistory
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const payload = req.body || {};
    const list = (payload.grocery_list || "").trim();
    if (!list) return res.status(400).json({ ok: false, error: "Missing grocery list" });

    const order = {
      createdAt: new Date(),
      runDate: payload.runDate || null,
      primaryStore: payload.primary_store || "",
      secondaryStore: payload.secondary_store || "",
      community: payload.community || "",
      streetAddress: payload.street_address || "",
      phone: payload.phone || "",
      groceryList: payload.grocery_list || "",
      notes: payload.grocery_notes || "",
      addOns: {
        fastFood: !!payload.addon_fast_food,
        liquor: !!payload.addon_liquor,
        printing: !!payload.addon_printing,
        ride: !!payload.addon_ride,
      },
      status: "submitted",
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

// Simple member portal page
app.get("/member", (req, res) => {
  if (!req.user) return res.redirect("/");

  const u = req.user;
  const renewal = u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A";

  const orders = (u.orderHistory || []).slice(0, 25);
  const orderHtml = orders.length
    ? orders
        .map((o) => {
          const created = o.createdAt ? new Date(o.createdAt).toLocaleString("en-CA") : "";
          return `<li><strong>${created}</strong> — ${o.primaryStore || "—"} — ${o.status || "submitted"}</li>`;
        })
        .join("")
    : `<li>No orders yet.</li>`;

  res.type("html").send(`
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>TGR Member Portal</title>
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;background:#0f1526;color:#fff}
          main{max-width:900px;margin:0 auto;padding:18px}
          .card{background:#121a2e;border:1px solid rgba(255,255,255,.14);border-radius:14px;padding:14px;margin:12px 0}
          a{color:#9fd7ff}
          .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
          .btn{display:inline-block;padding:10px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.18);text-decoration:none;color:#fff;font-weight:800}
          .btn.primary{background:#e3342f;border-color:rgba(0,0,0,.15)}
          .muted{opacity:.8}
        </style>
      </head>
      <body>
        <main>
          <div class="card">
            <h1 style="margin:0 0 8px">Member Portal</h1>
            <div class="muted">Signed in as <strong>${u.email}</strong></div>
            <div class="row" style="margin-top:10px">
              <a class="btn" href="${BASE_URL}/logout">Log out</a>
              <a class="btn primary" href="https://tobermorygroceryrun.ca/indexapp.html" target="_blank" rel="noopener">Go to Order Form</a>
            </div>
          </div>

          <div class="card">
            <h2 style="margin:0 0 8px">Membership</h2>
            <div>Level: <strong>${u.membershipLevel || "none"}</strong></div>
            <div>Status: <strong>${u.membershipStatus || "inactive"}</strong></div>
            <div>Renewal: <strong>${renewal}</strong></div>
          </div>

          <div class="card">
            <h2 style="margin:0 0 8px">Recent Orders</h2>
            <ul>${orderHtml}</ul>
          </div>

          <div class="card">
            <h2 style="margin:0 0 8px">API</h2>
            <p class="muted">For testing:</p>
            <ul>
              <li><a href="/api/me">/api/me</a></li>
              <li><a href="/api/orders">/api/orders</a></li>
            </ul>
          </div>
        </main>
      </body>
    </html>
  `);
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