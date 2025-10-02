import { connectDB } from "../lib/db.js";
import { getTransporter } from "../lib/mailer.js";
import Member from "../models/Member.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok:false, error:"Method not allowed" });
  try {
    await connectDB();
    const { fullName, name, mobile, email, aadhar = "", pan = "", project = "", paymentRef = "" } = req.body || {};
    const finalName = fullName || name;
    if (!finalName || !mobile || !email) return res.status(400).json({ ok:false, error:"Missing required fields" });

    const saved = await Member.create({ fullName: finalName, mobile, email, aadhar, pan, project, paymentRef });
    const memberId = "FWF" + saved._id.toString().slice(-6).toUpperCase();

    const transporter = getTransporter();
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "FWF Membership Details",
      text: `Dear ${finalName},\n\nYour membership is recorded.\nMember ID: ${memberId}\nPassword: (set via 'Forgot/Set Password' link)\n\nThank you!\nFWF`
    });

    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: process.env.SMTP_USER,
      subject: `New Member: ${finalName} (${memberId})`,
      text: `Name: ${finalName}\nMobile: ${mobile}\nEmail: ${email}\nProject: ${project || "-"}\nPaymentRef: ${paymentRef || "-"}`
    });

    return res.json({ ok:true, id: saved._id, memberId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok:false, error:String(err) });
  }
}