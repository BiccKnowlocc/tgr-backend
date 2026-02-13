const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("./models/User");


require("dotenv").config();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));


	const cors = require("cors");

app.use(cors({
  origin: [
    "https://tobermorygroceryrun.ca",
    "https://www.tobermorygroceryrun.ca"
  ],
  methods: ["GET","POST","OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));

	const mongoose = require("mongoose");

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));


// Sessions (required for Passport)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
  })
);

// Passport init
app.use(passport.initialize());
app.use(passport.session());

// Store user in session
passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (e) {
    done(e);
  }
});

//const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${BASE_URL}/auth/google/callback`,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = (profile.emails?.[0]?.value || "").toLowerCase();
        const photo = profile.photos?.[0]?.value || "";

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

  

// Home route
app.get("/", (req, res) => {
  if (req.user) {
    return res.send(`
      <h1>Logged in ✅</h1>
      <p>Name: ${req.user.displayName}</p>
      <p>Email: ${req.user.emails?.[0]?.value || ""}</p>
      <p><a href="/member">Go to Member Page</a></p>
      <p><a href="/logout">Logout</a></p>
    `);
  }

  res.send(`
    <h1>TGR Member Login</h1>
    <p><a href="/auth/google">Login with Google</a></p>
    <p><a href="/health">Health Check</a></p>
  `);
});

// Health route
app.get("/health", (req, res) => {
  res.send("OK server is running");
});

// Start login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);


// Callback after Google approves login
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/member");
  }
);

// Member page (protected)
app.get("/member", (req, res) => {
  if (!req.user) return res.redirect("/");

  const u = req.user;
  const renewal = u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A";

  // Simple perks/discounts defaults if arrays are empty
  const perks = (u.perks && u.perks.length) ? u.perks : [
    "Priority booking on run days",
    "Reduced extra-store fees (based on tier)",
    "Faster issue resolution support"
  ];

  const discounts = (u.discounts && u.discounts.length) ? u.discounts : [
    "Member discounts apply to service/delivery fees (where applicable)"
  ];

  const orderRows = (u.orderHistory || [])
    .slice()
    .reverse()
    .map((o) => {
      const created = o.createdAt ? new Date(o.createdAt).toLocaleDateString("en-CA") : "";
      const run = o.runDate ? new Date(o.runDate).toLocaleDateString("en-CA") : "—";
      const store = o.store || "—";
      const status = o.status || "submitted";
      const fees = (typeof o.totalFees === "number") ? `$${o.totalFees.toFixed(2)}` : "—";
      const groceries = (typeof o.totalGroceries === "number") ? `$${o.totalGroceries.toFixed(2)}` : "—";
      return `
        <tr>
          <td>${created}</td>
          <td>${run}</td>
          <td>${store}</td>
          <td><span class="badge">${status}</span></td>
          <td>${fees}</td>
          <td>${groceries}</td>
        </tr>
      `;
    })
    .join("");

  const manageUrl = process.env.SQUARE_MANAGE_MEMBERSHIP_URL || "#";
  const cancelUrl = process.env.SQUARE_CANCEL_MEMBERSHIP_URL || "#";

  res.send(`<!DOCTYPE html>
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
      .btn:focus-visible{outline:2px solid #fff;outline-offset:2px}
      .muted{color:var(--muted)}
      .tabs{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0}
      .tab{border:1px solid var(--line);background:rgba(255,255,255,.06);color:var(--text);padding:8px 12px;border-radius:999px;
        cursor:pointer;font-weight:800}
      .tab[aria-selected="true"]{background:var(--soft);border-color:rgba(227,52,47,.5)}
      .panel{display:none;margin-top:12px}
      .panel.active{display:block}
      ul{margin:8px 0 0 18px;padding:0}
      li{margin:6px 0}
      table{width:100%;border-collapse:collapse;margin-top:10px}
      th,td{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;font-size:.95rem}
      th{color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.06em}
      footer{padding:14px 0 0;color:var(--muted);font-size:.9rem}
      .warn{padding:10px 12px;border-radius:12px;border:1px solid rgba(227,52,47,.35);background:rgba(227,52,47,.10)}
      .small{font-size:.9rem}
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
            <div>
              <div class="pill">Name: <strong>${u.name || ""}</strong></div>
              <div class="pill">Status: <strong>${u.membershipStatus}</strong></div>
              <div class="pill">Level: <strong>${u.membershipLevel}</strong></div>
              <div class="pill">Renewal: <strong>${renewal}</strong></div>
            </div>
            <div class="row">
              <a class="btn ghost" href="/logout">Log out</a>
            </div>
          </div>

          <div class="tabs" role="tablist" aria-label="Portal sections">
            <button class="tab" id="tab-membership" aria-selected="true" aria-controls="panel-membership" type="button">Membership</button>
            <button class="tab" id="tab-perks" aria-selected="false" aria-controls="panel-perks" type="button">Perks & Discounts</button>
            <button class="tab" id="tab-orders" aria-selected="false" aria-controls="panel-orders" type="button">Order History</button>
          </div>

          <div id="panel-membership" class="panel active" role="tabpanel" aria-labelledby="tab-membership">
            <h2 style="margin:6px 0 0;font-size:1.05rem">Manage Membership</h2>
            <p class="muted small" style="margin:6px 0 10px">
              Use the buttons below to manage billing or request cancellation. Changes may take a short time to reflect on your account.
            </p>

            <div class="row">
              <a class="btn primary" href="${manageUrl}" target="_blank" rel="noopener">Manage / Pay Membership</a>
              <a class="btn ghost" href="${cancelUrl}" target="_blank" rel="noopener">Cancel / Request Cancellation</a>
            </div>

            <div style="margin-top:12px" class="warn small">
              Tip: If you think your membership level is wrong, contact <strong>members@tobermorygroceryrun.ca</strong> and we will correct it.
            </div>
          </div>

          <div id="panel-perks" class="panel" role="tabpanel" aria-labelledby="tab-perks">
            <h2 style="margin:6px 0 0;font-size:1.05rem">Your Perks</h2>
            <ul>${perks.map(p => `<li>${p}</li>`).join("")}</ul>

            <h2 style="margin:14px 0 0;font-size:1.05rem">Your Discounts</h2>
            <ul>${discounts.map(d => `<li>${d}</li>`).join("")}</ul>
          </div>

          <div id="panel-orders" class="panel" role="tabpanel" aria-labelledby="tab-orders">
            <h2 style="margin:6px 0 0;font-size:1.05rem">Order History</h2>
            <p class="muted small" style="margin:6px 0 8px">
              This list shows orders submitted through the TGR system. If something is missing, email <strong>orders@tobermorygroceryrun.ca</strong>.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Submitted</th>
                  <th>Run Date</th>
                  <th>Store</th>
                  <th>Status</th>
                  <th>Fees</th>
                  <th>Groceries</th>
                </tr>
              </thead>
              <tbody>
                ${orderRows || `<tr><td colspan="6" class="muted">No orders on file yet.</td></tr>`}
              </tbody>
            </table>
          </div>
        </section>

        <aside class="card">
          <h2 style="margin:0 0 8px;font-size:1.05rem">Quick Links</h2>
          <div class="row" style="flex-direction:column;align-items:stretch">
            <a class="btn primary" href="https://tobermorygroceryrun.ca/indexapp.html" target="_blank" rel="noopener">Place an Order</a>
            <a class="btn ghost" href="https://tobermorygroceryrun.ca/terms.html" target="_blank" rel="noopener">Terms & Conditions</a>
            <a class="btn ghost" href="mailto:orders@tobermorygroceryrun.ca">Email Orders</a>
            <a class="btn ghost" href="mailto:members@tobermorygroceryrun.ca">Email Membership</a>
          </div>

          <footer>
            <div>Need help? Email <strong>info@tobermorygroceryrun.ca</strong></div>
          </footer>
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
    </script>
  </body>
  </html>`);
});

// Logout
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("connect.sid"); // default session cookie name
      res.redirect("/");
    });
  });
});


	// Very simple admin check using ?key=YOUR_ADMIN_KEY
function requireAdmin(req, res, next) {
  if (req.query.key && req.query.key === process.env.ADMIN_KEY) return next();
  return res.status(401).send("Unauthorized. Add ?key=RonBullock2581! to the URL.");
}

// View all users (basic)
app.get("/admin/users", requireAdmin, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).limit(200);

  const rows = users
    .map(
      (u) => `
      <tr>
        <td>${u.name || ""}</td>
        <td>${u.email}</td>
        <td>${u.membershipStatus}</td>
        <td>${u.membershipLevel}</td>
        <td>${u.renewalDate ? new Date(u.renewalDate).toLocaleDateString("en-CA") : "N/A"}</td>
      </tr>
    `
    )
    .join("");

  res.send(`
    <h1>Admin: Users</h1>
    <p>Tip: You can update memberships using the endpoint below.</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr>
        <th>Name</th><th>Email</th><th>Status</th><th>Level</th><th>Renewal</th>
      </tr>
      ${rows}
    </table>
    <hr/>
    <h2>Update a member</h2>
    <p>Use this format:</p>
    <pre>/admin/set-membership?key=YOURKEY&email=test@gmail.com&level=member&status=active&renewal=2026-03-01</pre>
  `);
});

// Update membership for a specific email
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
    <p><a href="/admin/users?key=${encodeURIComponent(req.query.key)}">Back to users</a></p>
  `);
});



// Start server
	
	app.post("/api/order", async (req, res) => {
  try {
    // Your indexapp.html form fields
    const {
      full_name,
      email,
      phone,
      community,
      membership_status,
      primary_store,
      grocery_list,
      totalGroceries, // optional if you ever send it
      totalFees,      // optional if you ever send it
    } = req.body;

    if (!email || !full_name || !phone || !primary_store || !grocery_list) {
      return res.status(400).json({ ok: false, message: "Missing required fields." });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    // Find/create user by email (so even non-members get a customer record)
    let user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      user = await User.create({
        email: normalizedEmail,
        name: full_name,
        membershipLevel: "none",
        membershipStatus: "inactive",
        renewalDate: null,
        discounts: [],
        perks: [],
        orderHistory: [],
      });
    } else {
      // keep name fresh if they typed it differently
      if (!user.name) user.name = full_name;
      await user.save();
    }

    // Save an order entry
    user.orderHistory.push({
      runDate: null, // you can compute next run date later
      store: primary_store,
      totalGroceries: totalGroceries ? Number(totalGroceries) : 0,
      totalFees: totalFees ? Number(totalFees) : 0,
      status: "submitted",
      notes: `Community: ${community || ""} | Membership: ${membership_status || ""} | Phone: ${phone || ""}`,
    });

    await user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error("Order save error:", err);
    return res.status(500).json({ ok: false, message: "Server error saving order." });
  }
});
	const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});



