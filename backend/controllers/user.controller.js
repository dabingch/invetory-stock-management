const User = require("../models/User");
const asyncHandler = require("express-async-handler");

const registerUser = asyncHandler(async (req, res) => {
	const { email } = req.body;

	if (!email) {
		return res.status(400).json({ message: "Please add an email" });
	}

	res.send("Register User");
});

module.exports = {
	registerUser,
};
