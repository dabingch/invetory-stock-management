const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv").config();
const bodyParser = require("body-parser");
const cors = require("cors");
const connectDB = require("./models/db");
const PORT = process.env.PORT || 5000;

const app = express();

console.log(process.env.NODE_ENV);

connectDB();

app.listen(PORT, () => console.log(`Server listen on PORT:${PORT}`));
