const router = require("express").Router();
const authGuard = require("../auth/authGuard");
const Product = require("../models/productModel");
const cloudinary = require("cloudinary").v2;
const Order = require("../models/orderModel");
const userModel = require("../models/userModel");
const productModel = require("../models/productModel");

// create a add product route
router.post("/add", authGuard, async (req, res) => {
    // destructuring
    const { name, price, category, description } = req.body;

    // image
    const image = req.files.image;

    //validation
    if (!name || !price || !category || !description || !image) {
        return res.status(400).json({ msg: "Please fill all the fields." });
    }

    try {
        // upload image to cloudinary
        const uploadedImage = await cloudinary.uploader.upload(image.path, {
            folder: "products",
            crop: "scale",
        });

        // create a new product
        const newProduct = new Product({
            name,
            image: uploadedImage.secure_url,
            price,
            category,
            description,
        });

        // save product
        await newProduct.save();
        res.status(200).send("Success");
    } catch (err) {
        res.status(500).json({ msg: "Add Product Failed" });
    }
});

// get all products
router.get("/get-products", async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).json(products);
    } catch (err) {
        res.status(500).json({ msg: "Internal Server Error" });
    }
});

// get a single product
router.get("/get-products/:id", async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        res.status(200).json(product);
    } catch (err) {
        res.status(500).json({ msg: "Internal Server Error" });
    }
});

// update a product
router.put("/update_product/:id", authGuard, async (req, res) => {
    const { name, price, category, description } = req.body;
    const image = req.files.image;
    console.log(req.body);

    //validation
    if (!name || !price || !category || !description) {
        return res.status(400).json({ msg: "Please fill all the fields." });
    }
    try {
        const product = await Product.findById(req.params.id);
        if (image) {
            // upload image to cloudinary
            const uploadedImage = await cloudinary.uploader.upload(image.path, {
                folder: "products",
                crop: "scale",
            });
            product.image = uploadedImage.secure_url;
        }

        // get product
        product.name = name;
        product.price = price;
        product.category = category;
        product.description = description;

        // save product
        await product.save();
        res.status(200).send("Success");
    } catch (err) {
        res.status(500).json({ msg: "Add Product Failed" });
    }
});

// delete a product
router.delete("/delete_product/:id", authGuard, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.status(200).send("Success");
    } catch (err) {
        res.status(500).json({ msg: "Internal Server Error" });
    }
});
// search product
router.get("/search/:name", async (req, res) => {
    try{
        const product = await Product.find({
            name:{
                $regex:req.params.name,
                $options:'i'
            }
        });
        res.status(200).json(product);
    }catch(err){
        res.status(500).json({ msg: "Internal Server Error" });
    }
});

//count product, pending order, delivered order,users
router.get("/count", async (req, res) => {
    try{
        const productCount = await productModel.countDocuments({});
        const pendingOrderCount = await Order.countDocuments({status:"Pending"});
        const deliveredOrderCount = await Order.countDocuments({status:"Delivered"});
        const userCount = await userModel.countDocuments({});

        res.status(200).json({productCount,pendingOrderCount,deliveredOrderCount,userCount})
    }catch(err){
        res.status(500).json({ msg: "Internal Server Error" });
    }
});

module.exports = router;
