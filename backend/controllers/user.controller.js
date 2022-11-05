const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Token = require("../models/Token");
const sendEmail = require("../utils/sendEmail");

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
const loginUser = asyncHandler(async (req, res) => {
	// res.send("Login user");
	const { email, password } = req.body;

	// Validate request
	if (!email || !password) {
		return res
			.status(400)
			.json({ message: "Please add email and password!" });
	}

	// Check if user exists
	const user = await User.findOne({ email });

	if (!user) {
		return res.status(400).json({ message: "User does not exist!" });
	}

	// Check password
	const passwordIsCorrect = await bcrypt.compare(password, user.password);

	if (user && passwordIsCorrect) {
		// Generate token
		const token = generateToken(user._id);

		// Send HTTP-only cookie
		res.cookie("token", token, {
			path: "/",
			httpOnly: true,
			expires: new Date(Date.now() + 1000 * 86400),
			sameSite: "none",
			// production: true
			secure: false,
		});

		const { _id, username, email, photo, phone, bio } = user;
		res.status(200).json({
			_id,
			username,
			email,
			photo,
			phone,
			bio,
		});
	} else {
		res.status(400).json({ message: "Invalid email or password" });
	}
});

// logout
const logout = asyncHandler(async (req, res) => {
	// res.send("Logout");
	res.cookie("token", "", {
		path: "/",
		httpOnly: true,
		expires: new Date(Date.now() + 1000 * 86400),
		sameSite: "none",
		secure: true,
	});

	res.status(200).json({ message: "Logout successfully" });
});

// Get user
const getUser = asyncHandler(async (req, res) => {
	// res.send("Get User");
	const user = await User.findById(req.user._id);

	if (user) {
		const { _id, username, email, photo, phone, bio } = user;
		res.status(200).json({
			_id,
			username,
			email,
			photo,
			phone,
			bio,
		});
	} else {
		res.status(400).json({ message: "User not found!" });
	}
});

const loginStatus = asyncHandler(async (req, res) => {
	// res.send("Logged in!");
	const token = req.cookies.token;

	if (!token) {
		return res.json(false);
	}

	const verified = jwt.verify(token, process.env.JWT_SECRET);
	if (verified) {
		return res.json(true);
	}
	return res.json(false);
});

// Update user
const updateUser = asyncHandler(async (req, res) => {
	// res.send("Update User");
	const user = await User.findById(req.user._id);

	if (user) {
		const { username, email, photo, phone, bio } = user;
		user.email = email;
		user.username = req.body.username || username;
		user.photo = req.body.photo || photo;
		user.phone = req.body.phone || phone;
		user.bio = req.body.bio || bio;

		const updateUser = await user.save();
		res.status(201).json({
			username: updateUser.username,
			email: updateUser.email,
			photo: updateUser.photo,
			phone: updateUser.phone,
			bio: updateUser.bio,
		});
	} else {
		res.status(404).json({
			message: "User not found!",
		});
	}
});

// Change password
const changePassword = asyncHandler(async (req, res) => {
	// res.send("Change password");
	const user = await User.findById(req.user._id);

	if (!user) {
		return res.status(400).json({ message: "User not found!" });
	}

	const { oldPassword, password } = req.body;

	if (!oldPassword || !password) {
		return res
			.status(400)
			.json({ message: "Please input all credentials" });
	}

	const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

	if (passwordIsCorrect) {
		const hashedPassword = await bcrypt.hash(password, 10);
		user.password = hashedPassword;
		await user.save();
		res.status(200).json({ message: "Change password successfully!" });
	} else {
		res.status(400).json({ message: "Password incorrect!" });
	}
});

// Forget password
const forgotPassword = asyncHandler(async (req, res) => {
	// res.send("forgot password!");
	const { email } = req.body;
	const user = await User.findOne({ email });

	if (!user) {
		return res.status(404).json({ message: "User not found!" });
	}

	// Delete token if exists
	let existToken = await Token.findOne({ userId: user._id });
	if (existToken) {
		await existToken.deleteOne();
	}

	// Create reset token
	let token = crypto.randomBytes(32).toString("hex") + user._id;
	// console.log(token);
	const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
	// res.json(hashedToken);

	// Save token to database
	await new Token({
		userId: user._id,
		token: hashedToken,
		createdAt: Date.now(),
		expiresAt: Date.now() + 10 * (60 * 1000), // 10 mins
	}).save();

	// Reset url
	const resetUrl = `http://localhost:3000/resetpassword/${token}`;

	// Reset Email
	const message = `
      <h2>Hello ${user.username}</h2>
      <p>Please use the url below to reset your password</p>  
      <p>This reset link is valid for only 10 minutes.</p>
      <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
      <p>Regards...</p>
      <p>Dabing Team</p>
    `;
	const subject = "Password Reset Request";
	const send_to = user.email;
	const sent_from = process.env.EMAIL_USER;

	try {
		await sendEmail(subject, message, send_to, sent_from);
		res.status(200).json({ success: true, message: "Reset Email Sent" });
	} catch (err) {
		console.log(err);
		res.status(500).json({ message: "Email not sent, please try again" });
	}
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
	const { password } = req.body;
	const { resetToken } = req.params;

	// Hash token, then compare to Token in DB
	const hashedToken = crypto
		.createHash("sha256")
		.update(resetToken)
		.digest("hex");

	// Find token in database
	const userToken = await Token.findOne({
		token: hashedToken,
		expiresAt: { $gt: Date.now() },
	});

	if (!userToken) {
		res.status(404);
		throw new Error("Invalid or expired token");
	}

	// Find user
	const user = await User.findOne({ _id: userToken.userId });

	// Hash password
	const hashedPassword = await bcrypt.hash(password, 10);
	user.password = hashedPassword;
	await user.save();
	res.status(200).json({
		message: "Password reset successful, Please login!",
	});
});

module.exports = {
	registerUser,
	loginUser,
	logout,
	getUser,
	loginStatus,
	updateUser,
	changePassword,
	forgotPassword,
	resetPassword,
};
