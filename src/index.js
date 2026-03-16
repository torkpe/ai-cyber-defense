

require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const session = require("express-session");
const nodemailer = require("nodemailer");
const geoip = require("geoip-lite");

const { collection, ThreatLog } = require("./mongodb");
const { createModel, trainModel, predict, predictFutureThreat } = require("./mlModel");

const app = express();

/* ============================
   EMAIL TRANSPORTER
============================ */
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS // Gmail app password
    }
});

/* ============================
   MIDDLEWARE
============================ */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Track IP + device
app.use((req, res, next) => {
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const geo = geoip.lookup(ipAddress);
    const country = geo ? geo.country : "Unknown";
    const deviceInfo = req.headers['user-agent'];

    req.userCountry = country;
    req.userDevice = deviceInfo;

    next();
});

// ============================
// ADMIN AUTH MIDDLEWARE
// ============================
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.status(403).send("Access denied");
    }
    next();
}

/* ============================
   PASSWORD RESET TOKEN
============================ */
function generatePasswordResetToken() {
    const token = crypto.randomBytes(32).toString("hex");
    const expiry = Date.now() + 60 * 60 * 1000; // 1 hour
    return { token, expiry };
}

/* ============================
   VIEW ENGINE
============================ */
const templatePath = path.join(__dirname, "../templates");
app.set("view engine", "hbs");
app.set("views", templatePath);

/* ============================
   ROUTES
============================ */

// Home / Login / Signup
app.get("/", (req, res) => res.redirect("/home"));
app.get("/home", (req, res) => res.render("home", { user: req.session.user }));
app.get("/login", (req, res) => res.render("login"));
app.get("/signup", (req, res) => res.render("signup"));
app.get("/admin-dashboard", requireAdmin, (req, res) => {
    res.render("admin-dashboard");
});

// Logout
app.get("/logout", async (req, res) => {
    if (req.session.user) {
        await collection.updateOne(
            { _id: req.session.user.id },
            { $set: { activeSession: false } }
        );
    }
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.redirect("/login");
    });
});

// Email verification
app.get("/verify-email", async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.send("Invalid verification link.");

        const user = await collection.findOne({
            emailToken: token,
            emailTokenExpiry: { $gt: new Date() }
        });
        if (!user) return res.send("Token expired or invalid.");

        await collection.updateOne(
            { _id: user._id },
            { 
                $set: { isVerified: true },
                $unset: { emailToken: "", emailTokenExpiry: "" } 
            }
        );
console.log("Verification token received:", token);
        res.redirect("/login");
    } catch (err) {
        console.error("Email verification error:", err);
        res.status(500).send("Something went wrong.");
    }
});

/* ============================
   SIGNUP
============================ */
app.post("/signup", async (req, res) => {
    try {
        const { fullname, email, password, confirm_password } = req.body;

        if (password !== confirm_password) return res.send("Passwords do not match");

        const existingUser = await collection.findOne({ email });
        if (existingUser) return res.send("Email already registered");

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString("hex");
        const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

        await collection.create({
            fullname,
            email,
            password: hashedPassword,
            lastLoginCountry: req.userCountry,
            lastDevice: req.userDevice,
            isVerified: false,
            emailToken: token,
            emailTokenExpiry: tokenExpiry,
            activeSession: false
        });

        const verificationUrl = `${req.protocol}://${req.get("host")}/verify-email?token=${token}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify your email",
            html: `
                <h3>Hello ${fullname}</h3>
                <p>Click below to verify your account:</p>
                <a href="${verificationUrl}">Verify Email</a>
                <p>This link expires in 24 hours.</p>
            `
        });

        res.redirect("/login");
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).send("Internal Server Error");
    }
});

/* ============================
   LOGIN (WITH ACTIVE SESSION + AI DETECTION)
============================ */
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await collection.findOne({ email });
        if (!user) return res.send("User not found");

        // BLOCK CHECK (PUT IT HERE)
        if (user.isBlocked) {
            return res.send("Account blocked due to suspicious activity.");
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.send("Wrong password");

        if (!user.isVerified) return res.send("Please verify your email first");

        const country = req.userCountry;
        const device = req.userDevice;

        // === Suspicious login detection (country/device + AI) ===
        let suspicious = false;
        if (user.lastLoginCountry && user.lastLoginCountry !== country) suspicious = true;
        if (user.lastDevice && user.lastDevice !== device) suspicious = true;

        const behaviorFeatures = [
            suspicious ? 1 : 0,
            Math.random(), Math.random(), Math.random(),
            Math.random(), Math.random()
        ];
        const threatScore = await predict(behaviorFeatures);
        // === Risk Level Classification ===
        let riskLevel = "Low";

        if (threatScore > 0.75) {
            riskLevel = "High";
        } else if (threatScore > 0.45) {
            riskLevel = "Medium";
        }

        // === Log Threat Event (AI Framework Core) ===
        await ThreatLog.create({
            email: user.email,
            ipAddress: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            country,
            device,
            threatScore,
            riskLevel
        });

        if (threatScore > 0.7) suspicious = true;

        // === Active session or suspicious detected ===
        if (user.activeSession || suspicious) {
            const { token, expiry } = generatePasswordResetToken();

            await collection.updateOne(
                { _id: user._id },
                { $set: { passwordResetToken: token, passwordResetExpiry: expiry } }
            );

            const resetUrl = `${req.protocol}://${req.get("host")}/reset-password?token=${token}`;

            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: "Account Login Alert",
                html: `
                    <h3>Hello ${user.fullname}</h3>
                    <p>Someone tried to log in to your account.</p>
                    <p>If this wasn't you, click below to reset your password:</p>
                    <a href="${resetUrl}">Reset Password</a>
                    <p>This link expires in 1 hour.</p>
                `
            });

            return res.send("Suspicious login or active session detected. Alert email sent.");
        }

        // === Normal login ===
        req.session.user = { id: user._id, fullname: user.fullname, email: user.email };
        await collection.updateOne(
            { _id: user._id },
            { $set: { activeSession: true, lastLoginCountry: country, lastDevice: device } }
        );

        res.redirect("/home");

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send("Internal Server Error");
    }
});

/* ============================
   PASSWORD RESET
============================ */
app.get("/reset-password", async (req, res) => {
    const { token } = req.query;
    if (!token) return res.send("Invalid password reset link");

    const user = await collection.findOne({
        passwordResetToken: token,
        passwordResetExpiry: { $gt: Date.now() }
    });
    if (!user) return res.send("Token expired or invalid");

    res.render("reset-password", { token });
});

app.post("/reset-password", async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) return res.send("Passwords do not match");

    const user = await collection.findOne({
        passwordResetToken: token,
        passwordResetExpiry: { $gt: Date.now() }
    });
    if (!user) return res.send("Token expired or invalid");

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await collection.updateOne(
        { _id: user._id },
        {
            $set: { password: hashedPassword, activeSession: false },
            $unset: { passwordResetToken: "", passwordResetExpiry: "" }
        }
    );

    res.send("Password changed successfully. You can now log in.");
});

/* ============================
   AI THREAT HEATMAP API
============================ */
app.get("/api/threat-heatmap", async (req, res) => {
    try {
        const data = await ThreatLog.aggregate([
            {
                $group: {
                    _id: "$country",
                    totalThreats: { $sum: 1 },
                    highRisk: {
                        $sum: {
                            $cond: [{ $eq: ["$riskLevel", "High"] }, 1, 0]
                        }
                    }
                }
            },
            { $sort: { totalThreats: -1 } }
        ]);

        res.json({
            framework: "AI-Driven Predictive Cyber Defense Framework",
            description: "Real-Time Detection and Prevention of Emerging Cyber Threats",
            heatmap: data
        });

    } catch (err) {
        console.error("Heatmap error:", err);
        res.status(500).send("Error generating heatmap");
    }
});

/* ============================
   THREAT TREND OVER TIME API
============================ */
app.get("/api/threat-trend", async (req, res) => {
    try {
        const trend = await ThreatLog.aggregate([
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
                    },
                    totalThreats: { $sum: 1 },
                    highRisk: {
                        $sum: {
                            $cond: [{ $eq: ["$riskLevel", "High"] }, 1, 0]
                        }
                    }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        res.json(trend);

    } catch (err) {
        console.error(err);
        res.status(500).send("Trend error");
    }
});

/* ============================
   ATTACK PREDICTION API
============================ */
app.get("/api/attack-prediction", async (req, res) => {
    try {

        const trend = await ThreatLog.aggregate([
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
                    },
                    totalThreats: { $sum: 1 },
                    highRisk: {
                        $sum: {
                            $cond: [{ $eq: ["$riskLevel", "High"] }, 1, 0]
                        }
                    }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        const prediction = await predictFutureThreat(trend);

        res.json({
            framework: "AI-Driven Predictive Cyber Defense Framework",
            prediction
        });

    } catch (err) {
        console.error("Prediction error:", err);
        res.status(500).send("Prediction failed");
    }
});

/* ============================
   SECURITY DASHBOARD API
============================ */
app.get("/security-dashboard", async (req, res) => {
    try {
        const totalThreats = await ThreatLog.countDocuments();
        const highRiskCount = await ThreatLog.countDocuments({ riskLevel: "High" });

        res.json({
            framework: "AI-Driven Predictive Cyber Defense Framework",
            totalThreatEvents: totalThreats,
            highRiskThreats: highRiskCount,
            status: "AI Cyber Defense Active"
        });

    } catch (err) {
        console.error("Dashboard error:", err);
        res.status(500).send("Error loading dashboard");
    }
});

app.get("/admin/threats", requireAdmin, async (req, res) => {
    const threats = await ThreatLog.find().sort({ timestamp: -1 });
    res.json(threats);
});

app.post("/admin/block-user", requireAdmin, async (req, res) => {
    try {
        const { email } = req.body;

        await collection.updateOne(
            { email },
            { $set: { isBlocked: true } }
        );

        res.send("User blocked.");
    } catch (err) {
        console.error("Block error:", err);
        res.status(500).send("Error blocking user");
    }
});



/* ============================
   SERVER START
============================ */
async function startServer() {
    try {
        console.log("🔹 Creating AI model...");
        await createModel();
        console.log("🔹 Training AI model...");
        await trainModel("data.json");

        const port = process.env.PORT || 5000;
        app.listen(port, () => console.log(`Server running on port: ${port}`));

    } catch (err) {
        console.error("Fatal startup error:", err);
        process.exit(1);
    }
}

startServer();

