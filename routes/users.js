const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require("passport");

//User Model
const User = require("../models/User");

//Login page
router.get("/login", (req, res)=> res.render("login"));

//Register page
router.get("/register", (req, res)=> res.render("register"));

//Register handle
router.post("/register", (req, res)=>{
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //Check required fields
    if(!name || !email || !password || !password2){
        errors.push({msg: "Please fill in all fields"});
    }

    //Check passwords match
    if(password !== password2){
        errors.push({msg: "Paswords do not match"});
    }

    //Check password greater 5
    if(password.length < 6){
        errors.push({msg: "Password should be at least 6 characters"});
    }

    //Render register with error if any error
    if(errors.length > 0){
        res.render("register", {
            errors,
            name,
            email,
            password,
            password2
        });
    }else{
        //Validation Passed
        User.findOne({email: email}) //chech if user with that email is already registered
            .then(user => {
                if(user){
                    //User exits
                    errors.push({msg: "Email is already registered"});
                    res.render("register", {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                }else{
                    //User doesn't exits register
                    const newUser = new User({ //user object
                        name, //this is same is name: name
                        email,
                        password
                    });

                    //Hash password
                    bcrypt.genSalt(10, (err, salt) => { //generating salt
                        bcrypt.hash(newUser.password, salt, (err, hash)=>{ //generating hashed password
                            if(err) throw err;

                            //Set password to hashed
                            newUser.password = hash;
                            //Save user
                            newUser.save()
                                .then(user => {
                                    req.flash("success_msg", "You are now registered");
                                    res.redirect("/users/login");
                                })
                                .catch(err => console.log(err));
                        });
                    });
                }
            });
    }
});

//Login handle
router.post("/login", (req, res, next)=>{
    passport.authenticate("local", {
        successRedirect: "/dashboard",
        failureRedirect: "/users/login",
        failureFlash: true
    })(req, res, next);
});

//Logout handle
router.get("/logout", (req, res)=>{
    req.logOut();
    req.flash("success_msg", "You are logged out");
    res.redirect("/users/login");
})

module.exports = router;