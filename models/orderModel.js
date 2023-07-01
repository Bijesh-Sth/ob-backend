const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
    orderNumber: {
        type: Number,
        required: true,
        default: Math.floor(1000 + Math.random() * 90000).toString(),
    },
    cart: [
        {
            name: { type: String },
            price: { type: Number },
            quantity: { type: Number },
            category: { type: String },
            image: { type: String },
        },
    ],
    totalAmount: {
        type: Number,
        required: true,
    },
    shippingAddress: {
        type: String,
    },
    status: {
        type: String,
        default: "Pending",
    },
    orderedAt: {
        type: Date,
        default: Date.now,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    },
});

const Order = mongoose.model("Order", orderSchema);
module.exports = Order;
