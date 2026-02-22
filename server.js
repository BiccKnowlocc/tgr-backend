// ======= server.js (FULL CLEAN FILE) =======

const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const cors = require("cors");

const MongoStorePkg = require("connect-mongo");
const MongoStore = MongoStorePkg.default || MongoStorePkg;

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const { Client, Environment, WebhooksHelper } = require("square");
const User = require("./models/User");

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
];

const SQUARE_LINKS = {
  standard: process.env.SQUARE_LINK_STANDARD,
  route: process.env.SQUARE_LINK_ROUTE,
  access: process.env.SQUARE_LINK_ACCESS,
  accesspro: process.env.SQUARE_LINK_ACCESSPRO,
};

const SQUARE_PAY_LINKS = {
  groceries: process.env.SQUARE_PAY_GROCERIES_LINK,
  fees: process.env.SQUARE_PAY_FEES_LINK,
};

const SQUARE_WEBHOOK_SIGNATURE_KEY = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY || "";
const SQUARE_WEBHOOK_NOTIFICATION_URL = process.env.SQUARE_WEBHOOK_NOTIFICATION_URL || "";
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN || "";

const PLAN_MAP = {
  [process.env.SQUARE_PLAN_STANDARD_VARIATION_ID || ""]: "standard",
  [process.env.SQUARE_PLAN_ROUTE_VARIATION_ID || ""]: "route",
  [process.env.SQUARE_PLAN_ACCESS_VARIATION_ID || ""]: "access",
  [process.env.SQUARE_PLAN_ACCESSPRO_VARIATION_ID || ""]: "accesspro",
};

function squareClient() {
  return new Client({
    accessToken: SQUARE_ACCESS_TOKEN,
    environment: Environment.Production,
  });
}
