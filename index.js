const express = require("express");
const connectDB = require("./database/Database");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const multipart = require("connect-multiparty");

// environment variables
require("dotenv").config();

const app = express();

// express json
app.use(express.json());

connectDB();

// cors
const corsOptions = {
    origin: true,
    credentials: true,
    optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(multipart());

// set view engine
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUD_API_SECRET,
});

// create a route
app.get("/", (req, res) => {
    res.send("Hello World");
});

// routes configuration
// route

// middleware for user
app.use("/api/user", require("./controllers/userControllers.js"));

// middleware for product
app.use("/api/product", require("./controllers/productControllers.js"));

// middleware for order
app.use("/api/order", require("./controllers/orderController.js"));

// listen to the server
app.listen(process.env.PORT, () => {
    console.log(`Server running at port ${process.env.PORT}`);
});
