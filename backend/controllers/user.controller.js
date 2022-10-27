const User = require("../models/User");
const asyncHandler = require("express-async-handler");

const registerUser = asyncHandler(async (req, res) => {
	res.send("Register User");
});

module.exports = {
	registerUser,
};
