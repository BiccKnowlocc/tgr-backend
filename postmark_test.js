const postmark = require("postmark");

const client = new postmark.ServerClient(process.env.POSTMARK_SERVER_TOKEN);

client.sendEmail({
  From: "orders@tobermorygroceryrun.ca",
  To: "orders@tobermorygroceryrun.ca",        // change to your personal email to test deliverability
  Subject: "Hello from Postmark (TGR test)",
  HtmlBody: "<strong>Hello</strong> — this is a Postmark test from TGR.",
  TextBody: "Hello — this is a Postmark test from TGR.",
  MessageStream: "outbound",
}).then(() => {
  console.log("Sent OK");
}).catch((err) => {
  console.error("Send failed:", err?.message || err);
});