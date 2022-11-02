const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const generateToken = (id) => {
	return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

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

	// Generate token
	const token = generateToken(user._id);

	// Send HTTP-only cookie
	res.cookie("token", token, {
		path: "/",
		httpOnly: true,
		expires: new Date(Date.now() + 1000 * 86400),
		sameSite: "none",
		secure: true,
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
			token,
		});
	} else {
		res.status(400).json({ message: "Invalid user data" });
	}

	// res.send("Register User");
});

// Login user
const loginUser = asyncHandler(async (req, res) => {});

module.exports = {
	registerUser,
	loginUser,
};
