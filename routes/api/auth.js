const express = require('express');
const { model } = require('mongoose');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');


//router.get('/', auth, (req, res) => res.send('Auth route'));
router.get('/', auth, async (req, res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route POST api/auth
// @desc  Authonticate user & get token
// @access Public

router.post('/',[
    /*check('name', 'Name is required')
    .not()
    .isEmpty(),*/
    check('email', 'Please include valid email').isEmail(),
    //check('password','Please enter password with 6 or more charactors').isLength({min: 6})
    check('password','Password is required').exists()
], 
async (req, res) => {
    //console.log(req.body);
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }
    const {/*name,*/ email, password} = req.body;
    try{
        let user = await User.findOne({ email });
        // See if user exists
        if(!user){
           //return res.status(400).json({errors: [{msg: 'User already exists'}]});
           return res.status(400).json({errors: [{msg: 'invalid Credentials'}]});
        }
    
    // Get user gravatar
    /*const avatar = gravatar.url(email,{
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
    await user.save();*/
    // Return jsonwebtoken

    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch){
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
    }

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