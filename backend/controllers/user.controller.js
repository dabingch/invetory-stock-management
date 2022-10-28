const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");

const registerUser = asyncHandler(async (req, res) => {
	const { username, email, password } = req.body;

	if (!username || !email || !password) {
		return res.status(400).json({ message: "Please fill in all fields!" });
	}

	if (password.length < 6) {
		return res
			.status(400)
			.json({ message: "Password must be up to 6 characters!" });
	}

	// Check if user email already exists
	const userExist = await User.findOne({ email });

	if (userExist) {
		return res.status(400).json({ message: "User email already exists!" });
	}

	const hashedPassword = await bcrypt.hash(password, 10);

	// Create new User
	const user = await User.create({
		username,
		email,
		password: hashedPassword,
	});

	if (user) {
		const { _id, username, email, photo, phone, bio } = user;
		res.status(201).json({
			_id,
			username,
			email,
			photo,
			phone,
			bio,
		});
	} else {
		res.status(400).json({ message: "Invalid user data" });
	}

	res.send("Register User");
});

module.exports = {
	registerUser,
};
