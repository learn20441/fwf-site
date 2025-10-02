import nodemailer from "nodemailer";

let cached = global._mailer;
if (!cached) cached = global._mailer = { transporter: null };

export function getTransporter() {
  if (cached.transporter) return cached.transporter;
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || "true") === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  cached.transporter = transporter;
  return transporter;
}