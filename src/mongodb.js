const mongoose = require("mongoose");

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log("Connected to MongoDB Atlas");
})
.catch((err) => {
    console.log("Failed to connect to MongoDB", err);
});



const UserSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    lastLoginCountry: {   // <-- add this
        type: String,
        default: "Unknown"
    },
    lastDevice: {         // <-- add this
        type: String,
        default: "Unknown"
    },
    isVerified: {           // <-- add this
        type: Boolean,
        default: false
    },
     // ADD THESE
    emailToken: {
       type: String
    },
    emailTokenExpiry: {
       type: Date
    },

     // NEW FIELDS FOR ACTIVE SESSION & PASSWORD RESET ALERT
    activeSession: {        // tracks if the user is currently logged in
        type: Boolean,
        default: false
    },
    passwordResetToken:{
       type: String
    },   // token for resetting password
    passwordResetExpiry: {
       type: Date
    },     // expiry time for the reset token
    isBlocked: {
        type: Boolean,
        default: false
    }
});

const collection = new mongoose.model("Collection1", UserSchema);


/* ============================
   THREAT LOG SCHEMA
============================ */

const ThreatSchema = new mongoose.Schema({
    email: String,
    ipAddress: String,
    country: String,
    device: String,
    threatScore: Number,
    riskLevel: {
        type: String,
        enum: ["Low", "Medium", "High"]
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const ThreatLog = mongoose.model("ThreatLog", ThreatSchema);


module.exports = {collection, ThreatLog};


//password
//1fokYEMUuPCRwyKF