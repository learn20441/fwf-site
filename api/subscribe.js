import { connectDB } from "../lib/db.js";
import { getTransporter } from "../lib/mailer.js";
import Subscription from "../models/Subscription.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method not allowed" });
  
  try {
    await connectDB();
    const { email } = req.body || {};
    
    if (!email) {
      return res.status(400).json({ ok: false, error: "Email is required" });
    }
    
    // Check if email is already subscribed
    const existingSubscription = await Subscription.findOne({ email });
    if (existingSubscription) {
      if (existingSubscription.isActive) {
        return res.status(409).json({ ok: false, error: "Email is already subscribed" });
      } else {
        // Reactivate existing subscription
        existingSubscription.isActive = true;
        existingSubscription.subscribedAt = new Date();
        await existingSubscription.save();
        
        // Send welcome back email
        try {
          const transporter = getTransporter();
          await transporter.sendMail({
            from: process.env.MAIL_FROM,
            to: email,
            subject: "Welcome Back to FWF Updates!",
            html: `
              <h2>Welcome Back!</h2>
              <p>You've successfully resubscribed to receive updates from Future With Foundation (FWF).</p>
              <p>Thank you for your continued support!</p>
              <br>
              <p>Best regards,<br>The FWF Team</p>
            `
          });
        } catch (emailError) {
          console.error("Email sending failed:", emailError);
        }
        
        return res.status(200).json({ ok: true, message: "Successfully resubscribed to updates!" });
      }
    }
    
    // Create new subscription
    const subscription = await Subscription.create({ email });
    
    // Send welcome email
    try {
      const transporter = getTransporter();
      await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: email,
        subject: "Welcome to FWF Updates!",
        html: `
          <h2>Welcome to Future With Foundation!</h2>
          <p>Thank you for subscribing to our updates.</p>
          <p>You'll now receive notifications about our latest projects, impact stories, and opportunities to get involved.</p>
          <br>
          <p>Best regards,<br>The FWF Team</p>
        `
      });
      
      // Notify admin
      await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: process.env.SMTP_USER,
        subject: "New Newsletter Subscription",
        text: `New subscription from: ${email}`
      });
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
      // Continue even if email fails
    }
    
    return res.status(201).json({ ok: true, message: "Successfully subscribed to updates!" });
    
  } catch (error) {
    console.error("Subscription error:", error);
    if (error.code === 11000) {
      return res.status(409).json({ ok: false, error: "Email is already subscribed" });
    }
    return res.status(500).json({ ok: false, error: "Internal server error" });
  }
}