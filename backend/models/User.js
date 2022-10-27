const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
	{
		username: {
			type: String,
			required: [true, "Please add a name"],
		},
		email: {
			type: String,
			required: [true, "Please add a email"],
			unique: true,
			trim: true,
			match: [
				/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
				"Please enter a valid email",
			],
		},
		password: {
			type: String,
			required: [true, "Please add a password"],
			minLength: [6, "Password too short"],
			maxLength: [32, "Password too long"],
		},
		photo: {
			type: String,
			// required: [true, "Please add a photo"],
			default:
				"https://robohash.org/bac6fa37fec6161545c9d68fbe875cb0?set=set4&bgset=&size=400x400",
		},
		phone: {
			type: String,
			default: "+61",
		},
		bio: {
			type: String,
			default: "bio",
			maxLength: [250, "bio too long"],
		},
	},
	{
		timestamps: true,
	}
);

module.exports = mongoose.model("User", userSchema);
