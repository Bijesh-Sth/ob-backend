const authGuard = require("../auth/authGuard");
const Order = require("../models/orderModel");

const router = require("express").Router();

router.post("/create", authGuard, async (req, res) => {
    const { cart, totalAmount, shippingAddress } = req.body;

    if (!(cart && totalAmount && shippingAddress)) {
        return res.status(400).json({ msg: "All fields are required" });
    }

    try {
        const newOrder = new Order({
            cart,
            totalAmount,
            shippingAddress,
            user: req.user.id,
        });

        await newOrder.save();

        res.status(200).json({ msg: "Order created successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: "Order creation failed" });
    }
});

router.get("/getOrdersByUserId", authGuard, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user.id });
        res.status(200).json({ orders });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: error });
    }
});

router.get("/getAllOrders", authGuard, async (req, res) => {
    try {
        const orders = await Order.find({});
        res.status(200).json({ orders });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: error });
    }
});

//change order status
router.put("/change_status/:id", async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        order.status = req.body.status;
        await order.save();
        res.status(200).json({ msg: "Order status changed successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: error });
    }
});
module.exports = router;
