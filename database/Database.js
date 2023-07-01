const connectDB = ()=>{
    // mongoose connection
    const mongoose = require('mongoose');
    mongoose.connect(process.env.DB_URL).then(()=>{
        console.log(`DB CONNECTED ${process.env.DB_URL}`);
    })
}

module.exports = connectDB;