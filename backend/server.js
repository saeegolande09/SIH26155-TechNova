const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcryptjs");

require("dotenv").config();

// ===============================
// ROUTES
// ===============================

const reportRoutes = require("./routes/reportRoutes");
const aiTrainingRoutes = require("./routes/aiTrainingRoutes");
const configRoutes = require("./routes/configRoutes");
const auditRoutes = require("./routes/auditRoutes");
const remediationRoutes = require("./routes/remediationRoutes");
const findingRoutes = require("./routes/findingRoutes");
const securityPostureRoutes = require("./routes/securityPostureRoutes");
const driftRoutes = require("./routes/driftRoutes");
const riskRoutes = require("./routes/riskRoutes");
const exposureRoutes = require("./routes/exposureRoutes");
const comparisonRoutes = require("./routes/comparisonRoutes");

// ===============================
// MODELS
// ===============================

const Device = require("./models/Device");
const Configuration = require("./models/Configuration");
const Audit = require("./models/Audit");
const Finding = require("./models/Finding");
const User = require("./models/User");

// ===============================
// APP
// ===============================

const app = express();

const PORT = process.env.PORT || 5000;

// ===============================
// MONGODB ATLAS
// ===============================

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB Atlas connected successfully!");
    })
    .catch((error) => {
        console.error(
            "MongoDB connection failed:",
            error.message
        );
    });

// ===============================
// EJS
// ===============================

app.set("view engine", "ejs");

app.set(
    "views",
    path.join(__dirname, "views")
);

// ===============================
// MIDDLEWARE
// ===============================

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(express.json());

// ===============================
// SESSION
// ===============================

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "netsentry-secret",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// ===============================
// MAKE USER AVAILABLE TO ALL EJS VIEWS
// ===============================

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// ===============================
// AUTH MIDDLEWARE
// ===============================

function requireLogin(req, res, next) {

    if (!req.session.user) {
        return res.redirect("/");
    }

    next();
}

function requireAdmin(req, res, next) {

    if (!req.session.user) {
        return res.redirect("/");
    }

    if (req.session.user.role !== "admin") {
        return res.status(403).send(
            "Access denied. Admin privileges required."
        );
    }

    next();
}

// ===============================
// PROTECTED ROUTES
// ===============================

app.use(
    "/configurations",
    requireLogin,
    configRoutes
);

app.use(
    "/audits",
    requireLogin,
    auditRoutes
);

app.use(
    "/findings",
    requireLogin,
    findingRoutes
);

app.use(
    "/remediations",
    requireLogin,
    remediationRoutes
);

app.use(
    "/security-posture",
    requireLogin,
    securityPostureRoutes
);

app.use(
    "/drift",
    requireLogin,
    driftRoutes
);

app.use(
    "/risk",
    requireLogin,
    riskRoutes
);

app.use(
    "/exposure",
    requireLogin,
    exposureRoutes
);

app.use(
    "/comparison",
    requireLogin,
    comparisonRoutes
);

app.use(
    "/reports",
    requireLogin,
    reportRoutes
);

app.use(
    "/ai-training",
    requireLogin,
    aiTrainingRoutes
);

// ===============================
// LOGIN PAGE
// ===============================

app.get("/", (req, res) => {

    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.render("pages/login");
});

// ===============================
// LOGIN
// ===============================

app.post("/login", async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;

        if (!username || !password) {

            return res.status(400).send(
                "Username and password are required."
            );
        }

        const user = await User.findOne({
            username: username.trim()
        });

        if (!user) {

            return res.status(401).send(
                "Invalid username or password."
            );
        }

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordMatch) {

            return res.status(401).send(
                "Invalid username or password."
            );
        }

        req.session.user = {
            id: user._id.toString(),
            username: user.username,
            email: user.email,
            role: user.role
        };

        console.log(
            "Login successful:",
            user.username,
            user.role
        );

        res.redirect("/dashboard");

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).send(
            "Login failed."
        );
    }
});

// ===============================
// REGISTER PAGE
// ===============================

app.get("/register", (req, res) => {

    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.render("pages/register");
});

// ===============================
// REGISTER
// ===============================

app.post("/register", async (req, res) => {

    try {

        const {
            username,
            email,
            password,
            confirmPassword
        } = req.body;

        if (
            !username ||
            !email ||
            !password ||
            !confirmPassword
        ) {

            return res.status(400).send(
                "All fields are required."
            );
        }

        if (password !== confirmPassword) {

            return res.status(400).send(
                "Passwords do not match."
            );
        }

        if (password.length < 6) {

            return res.status(400).send(
                "Password must contain at least 6 characters."
            );
        }

        const existingUser =
            await User.findOne({
                $or: [
                    {
                        username:
                            username.trim()
                    },
                    {
                        email:
                            email.trim().toLowerCase()
                    }
                ]
            });

        if (existingUser) {

            return res.status(409).send(
                "Username or email already exists."
            );
        }

        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );

        const newUser =
            await User.create({

                username:
                    username.trim(),

                email:
                    email.trim().toLowerCase(),

                password:
                    hashedPassword,

                role: "user"
            });

        console.log(
            "New user registered:",
            newUser.username
        );

        res.redirect("/");

    } catch (error) {

        console.error(
            "Registration error:",
            error
        );

        res.status(500).send(
            "Account creation failed."
        );
    }
});

// ===============================
// LOGOUT
// ===============================

app.get("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {

            console.error(
                "Logout error:",
                error
            );

            return res.status(500).send(
                "Logout failed."
            );
        }

        res.redirect("/");
    });
});

// ===============================
// DASHBOARD
// ===============================

app.get(
    "/dashboard",
    requireLogin,
    async (req, res) => {

        try {

            const userId = req.session.user.id;


            // ==========================================
            // GET CURRENT USER'S DEVICES
            // ==========================================

            const devices = await Device.find({
                user: userId
            }).select("_id");


            const deviceIds = devices.map(
                device => device._id
            );


            // ==========================================
            // TOTAL DEVICES
            // ==========================================

            const totalDevices =
                devices.length;


            // ==========================================
            // TOTAL CONFIGURATIONS
            // ==========================================

            const totalConfigurations =
                await Configuration.countDocuments({
                    device: {
                        $in: deviceIds
                    }
                });


            // ==========================================
            // COMPLETED AUDITS
            // ==========================================

            const completedAudits =
                await Audit.countDocuments({
                    device: {
                        $in: deviceIds
                    },
                    status: "Completed"
                });


            // ==========================================
            // AVERAGE SECURITY SCORE
            // ==========================================

            const scoreResult =
                await Device.aggregate([

                    {
                        $match: {
                            user: userId
                        }
                    },

                    {
                        $group: {

                            _id: null,

                            averageScore: {
                                $avg: "$securityScore"
                            }

                        }
                    }

                ]);


            const averageScore =
                scoreResult.length > 0
                    ? Math.round(
                        scoreResult[0].averageScore
                    )
                    : 0;


            // ==========================================
            // CRITICAL FINDINGS
            // ==========================================

            const criticalFindings =
                await Finding.countDocuments({
                    device: {
                        $in: deviceIds
                    },
                    severity: "Critical",
                    status: "Open"
                });


            // ==========================================
            // HIGH FINDINGS
            // ==========================================

            const highFindings =
                await Finding.countDocuments({
                    device: {
                        $in: deviceIds
                    },
                    severity: "High",
                    status: "Open"
                });


            // ==========================================
            // RECENT AUDITS
            // ==========================================

            const recentAudits =
                await Audit
                    .find({
                        device: {
                            $in: deviceIds
                        }
                    })
                    .populate("device")
                    .sort({
                        createdAt: -1
                    })
                    .limit(5);


            // ==========================================
            // RENDER DASHBOARD
            // ==========================================

            res.render(
                "pages/dashboard",
                {
                    totalDevices,

                    totalConfigurations,

                    completedAudits,

                    averageScore,

                    criticalFindings,

                    highFindings,

                    recentAudits
                }
            );


        } catch (error) {

            console.error(
                "Dashboard error:",
                error
            );

            res.status(500).send(
                "Failed to load dashboard"
            );
        }
    }
);

// ===============================
// ADMIN TEST
// ===============================

app.get(
    "/admin",
    requireAdmin,
    (req, res) => {

        res.send(
            "Admin access granted. Logged in as: " +
            req.session.user.username
        );
    }
);

// ===============================
// START SERVER
// ===============================

app.listen(
    PORT,
    () => {

        console.log(
            `NETSENTRY server running at http://localhost:${PORT}`
        );
    }
);