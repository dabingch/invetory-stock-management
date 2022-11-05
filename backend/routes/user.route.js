const express = require("express");
const router = express.Router();
const {
	registerUser,
	loginUser,
	logout,
	getUser,
	loginStatus,
	updateUser,
	changePassword,
	forgotPassword,
	resetPassword,
} = require("../controllers/user.controller");
const protect = require("../middleware/authMiddleware");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/forgotpassword", forgotPassword);
router.get("/logout", logout);
router.get("/getuser", protect, getUser);
router.get("/loggedin", loginStatus);
router.put("/updateuser", protect, updateUser);
router.put("/changepassword", protect, changePassword);
router.put("/resetpassword/:resetToken", resetPassword);

module.exports = router;
