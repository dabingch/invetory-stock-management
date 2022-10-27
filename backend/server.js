const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv").config();
const bodyParser = require("body-parser");
const cors = require("cors");
const connectDB = require("./models/db");
const userRoute = require("./routes/user.route");
const errorHandler = require("./middleware/errorHandler");

const PORT = process.env.PORT || 5000;

const app = express();

console.log(process.env.NODE_ENV);

connectDB();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

// Routes Middleware
app.use("/api/users", userRoute);

// Routes
app.get("/", (req, res) => res.send("Home Page"));

app.use(errorHandler);

mongoose.connection.once("open", () => {
	console.log("Connected to MongoDB");
	app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});

mongoose.connection.on("error", (err) => {
	console.log(err);
	// logEvents(`${err.no}: ${err.code}\t${err.syscall}\t${err.hostname}`, 'mongoErrLog.log')
});
