const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  studentId: { type: String, required: true },
  department: { type: String, required: true },
  password: { type: String, required: true },
  savedNotes: [
    { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'Note' 
    }
  ]
}, { timestamps: true });


// 🔐 HASH PASSWORD (CORRECTED)
// 1. Removed 'next' from the arguments
userSchema.pre("save", async function () { 
  
  // 2. Simply return if password isn't modified
  if (!this.isModified("password")) return; 

  // 3. Hash the password
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  
  // 4. No need to call next() - the async function finishing signals success
});


// 🔑 JWT METHOD
userSchema.methods.jwtToken = function () {
  return jwt.sign(
    {
      id: this._id,
      email: this.email
    },
    process.env.JWT_SECRET || "supersecretkey",
    {
      expiresIn: "1d"
    }
  );
};

module.exports = mongoose.model("User", userSchema);