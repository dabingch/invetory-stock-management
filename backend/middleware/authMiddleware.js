const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
	const token = req.cookies.token;
	// console.log(req.cookies);

	if (!token) {
		return res
			.status(401)
			.json({ message: "Not authenticated, please login!" });
	}

	// Verify token
	const verified = jwt.verify(token, process.env.JWT_SECRET);
	const user = await User.findById(verified.id).select("-password");

	if (!user) {
		return res.status(401).json({ message: "User not found!" });
	}

	req.user = user;
	next();
});

module.exports = protect;
