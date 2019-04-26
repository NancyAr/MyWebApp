const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//User model
const User = require('../models/User');
//login page
router.get('/login', (req,res)=> res.render("login"));

//resister page
router.get('/register', (req,res)=> res.render("register"));

//register handle
router.post('/register', (req,res)=> {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //check required fields
    if(!name || !email || !password || !password2){
        errors.push({ msg: 'Please fill in all fields'});
    }

    //checking if passwords match
    if(password != password2){
        errors.push({ msg: 'Passwords do not match!'});
    }

    //checking pasword length 8 min
    if(password.length < 8){
        errors.push({ msg: 'Password should be at least 6 character'})
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    }
    else {
        //user passed validation
        User.findOne({ email: email})
            .then(user => {
                if(user) {
                    //user already exits (registered)
                    errors.push({ msg: 'Email already taken.'})
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });

                } else {
                    const newUser = new User ({
                        name,
                        email,
                        password
                    });

                    //Hashing password using salt from bcrypt
                    //salt is a random text added to the string to be hashed
                    bcrypt.genSalt(10, (err, salt) => {
                     bcrypt.hash(newUser.password, salt, (err, hash)=> {
                         
                         if(err) throw err;
                         //set password to the hash generated
                         newUser.password = hash;

                         //save the user
                         newUser.save()
                            .then(user => {
                                req.flash('success_msg','You are now registered! Login!')
                                res.redirect('/user/login');
                            })
                            .catch(err => console.log(err));
                     })
                    })
                }
            });
    }
});

//Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/user/login',
        failureFlash: true
    })(req, res, next);

});

//Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg','You are logged out!');
    res.redirect('/user/login');

});
module.exports = router;