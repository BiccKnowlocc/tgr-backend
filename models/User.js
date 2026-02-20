// DEPLOY MARKER a30a136


const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema(
  {
    createdAt: { type: Date, default: Date.now },
    runDate: { type: Date, default: null },
    store: { type: String, default: "" },
    totalGroceries: { type: Number, default: 0 },
    totalFees: { type: Number, default: 0 },
    status: { type: String, default: "submitted" }, // submitted / paid / delivered / issue
    notes: { type: String, default: "" },
  },
  { _id: true }
);

const UserSchema = new mongoose.Schema(
  {
    googleId: { type: String, default: "", index: true },
    email: { type: String, required: true, unique: true, index: true },
    name: { type: String, default: "" },
    photo: { type: String, default: "" },

    membershipLevel: { type: String, default: "none" }, // none / standard / route / access / access_pro
    membershipStatus: { type: String, default: "inactive" }, // inactive / active / cancelled
    renewalDate: { type: Date, default: null },

    discounts: { type: [String], default: [] },
    perks: { type: [String], default: [] },

    // NEW: profile blob for saved addresses + future extensibility
    profile: {
      type: mongoose.Schema.Types.Mixed,
      default: () => ({ version: 1, defaultId: "", addresses: [] }),
    },

    orderHistory: { type: [OrderSchema], default: [] },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);