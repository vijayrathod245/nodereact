const express = require('express');
const { model } = require('mongoose');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User');
//router.get('/', (req, res) => res.send('User route'));

// @route POST api/users
// @desc  Register user
// @access Public

router.post('/',[
    check('name', 'Name is required')
    .not()
    .isEmpty(),
    check('email', 'Please include valid email').isEmail(),
    check('password','Please enter password with 6 or more charactors').isLength({min: 6})
], 
async (req, res) => {
    //console.log(req.body);
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }
    const {name, email, password} = req.body;
    try{
        let user = await User.findOne({ email });
        // See if user exists
        if(user){
           return res.status(400).json({errors: [{msg: 'User already exists'}]});
        }
    
    // Get user gravatar
    const avatar = gravatar.url(email,{
        s:'200',
        r:'pg',
        d:'mm'
    })
    user = new User({
        name,
        email,
        avatar,
        password
    });
    // Encypt password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password,salt);
    await user.save();
    // Return jsonwebtoken
    const payload = {
        user:{
            id: user.id
        }
    }

    jwt.sign(payload, config.get('jwtSecret'),{expiresIn: 360000}, (err, token) => {
        if(err) throw err;
        res.json({ token });
    });

    //res.send('User registered');
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});
module.exports = router;