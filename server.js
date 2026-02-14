require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const mongoose = require("mongoose");

const User = require("./models/User");

const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

const app = express();

// Fix common bad URL paste like: /https://tgr-backend.onrender.com/...
app.get(/^\/https?:\/\/.*/i, (req, res) => {
  return res.redirect("/");
});


// IMPORTANT for Render (cookies behind proxy)
app.set("trust proxy", 1);

// Body parsing
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));

// Static files (logo, etc.)
app.use(express.static(__dirname));

// CORS: allow your website to call your backend with cookies
app.use(
  cors({
    origin: ["https://tobermorygroceryrun.ca", "https://www.tobermorygroceryrun.ca"],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: true, // REQUIRED for cookies/sessions
  })
);

// Mongo
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Sessions (cookie must be cross-site compatible)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,      // Render is https
      sameSite: "none",  // cross-site cookie
    },
  })
);

// Passport init
app.use(passport.initialize());
app.use(passport.session());

// Auth helpers
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, error: "Not logged in" });
}

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

// Home route
app.get("/", (req, res) => {
  if (req.user) {
    return res.send(`
      <h1>Logged in ✅</h1>
      <p>Name: ${req.user.name || ""}</p>
      <p>Email: ${req.user.email || ""}</p>
      <p><a href="/member">Go to Member Page</a></p>
      <p><a href="/logout">Logout</

	const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});