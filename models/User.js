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

    membershipLevel: { type: String, default: "none" }, // none / member / runner / access
    membershipStatus: { type: String, default: "inactive" }, // inactive / active / cancelled
    renewalDate: { type: Date, default: null },

    discounts: { type: [String], default: [] },
    perks: { type: [String], default: [] },

    orderHistory: { type: [OrderSchema], default: [] },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
