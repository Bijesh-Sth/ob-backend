const router = require('express').Router();
const User = require("../models/userModel");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');


router.get('/test', (req,res) => {
    res.send("Welcome");
});


// ANCHOR REGISTER API
// ******************************************** REGISTER API ********************************************
router.post('/register', async (req, res)=>{
    // console.log(req.body);

    // unpacking
    const {fname, lname, email, password} = req.body;

    // validation
    if(!(fname && lname && email && password)){
        return res.status(400).json({msg: "All fields are required"})
    }



    try {
        // check existing user
        const userExists = await User.exists({email});

        if(userExists){
            return res.status(400).json({msg: "User already exists."})
        }

        const salt = await bcrypt.genSaltSync(10);
        const passwordHash = await bcrypt.hashSync(password, salt);

        const newUser = new User({
            fname: fname,
            lname: lname,
            email: email,
            password: passwordHash
        });
        newUser.save()

        res.json({msg: "User registered successfully"})

    } catch (error) {
        res.status(500).json({msg:"User registration failed"})
    }

    // res.send('Register');
})



// ANCHOR LOGIN API 
// ******************************************** LOGIN API ********************************************
router.post('/login', async(req, res)=>{
    const {email, password} = req.body;
    
    // validation
    if(!(email && password)){
        return res.status(400).json({msg: "All fields are required"})
    }

    try{
        const userExists = await User.findOne({email});
        
        // check if user exists
        if(!userExists){
            return res.status(403).json({msg:"User not found."})
        }

        // check if password is correct
        const validatePassword = await bcrypt.compareSync(password, userExists.password);
        if(!validatePassword){
            return res.status(403).json({msg:"Incorrect Password"});
        }

        const token = jwt.sign({id: userExists._id}, process.env.JWT_SECRET);

        // Cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            expires: new Date(Date.now() + 24*60*60*1000)
        })
        
        res.json({
            token: token,
            user: userExists,
            msg: "Welcome",
        });

        res.send();

    }catch(error){
        return res.status(500).json({msg:"Login Failed"})
    }
    })
    //forgot password
    router.post('/forgotpassword', async(req, res)=>{
        const {email} = req.body;
        //validation
        if(!email){
            return res.status(400).json({msg: "All fields are required"})
        }
        try{
            //check if user exists
            const user = await User.findOne({email});
            if(!user){
                return res.status(403).json({msg:"User not found."})
            }
            //create a reset token
            const secret = process.env.JWT_SECRET + user.password;
            const token = jwt.sign(
                {
                    id: user._id,
                    email: user.email
                },
                secret,
                {expiresIn: '10m'}
            );
            //create a reset link
            const resetLink = `http://localhost:5000/api/user/resetpassword/${user._id}/${token}`;
            console.log(email);
            console.log(resetLink);
            //send reset link to user's email
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'bijesh.burnermail@gmail.com',
                    pass: 'whipnmijtemmaham'
                }
            });
            var mailOptions = {
                from: 'bijesh.burnermail@gmail.com',
                to: email,
                subject: 'Reset Password',
                text: `Click on this link to reset your password: ${resetLink}`
            };
            //send mail
            transporter.sendMail(mailOptions, (error, info)=>{
                if(error){
                    console.log(error);
                }
                else{
                    console.log('Email sent: ' + info.response);
                }
            })
        
            

        }
        catch(error){
            return res.status(500).json({msg:"Verify Token Failed"})
        } 
    })
    //reset password
    router.get('/resetpassword/:id/:token', async(req, res)=>{
        const {id, token} = req.params;

        const oldUser = await User.findById({_id: id});
        if(!oldUser){
            return res.status(403).json({msg:"User not found."})
        }

        try{
            //verify token
            secret = process.env.JWT_SECRET + oldUser.password;
            const verifyToken = jwt.verify(token, secret);
            if(verifyToken){
                res.render('index', {email: verifyToken.email})
            }

        }

        catch(error){
            return res.status(500).json({msg:"Server Error"})
        }


    })
    //update password
    router.post('/resetpassword/:id/:token', async(req, res)=>{
        const {id, token} = req.params;
        const {password} = req.body;

        const oldUser = await User.findById({_id: id});
        if(!oldUser){
            return res.status(403).json({msg:"User not found."})
        }
        const secret = process.env.JWT_SECRET + oldUser.password;
        
        try{
            jwt.verify(token, secret);
            const hashPassword = await bcrypt.hashSync(password, 10);
            await User.findOneAndUpdate({_id: id}, {password: hashPassword});
            console.log(password);
            res.json({msg: "Password updated successfully"})

        }
        catch(error){
            return res.status(500).json({msg:"Server Error"})
        }

    })

module.exports = router;