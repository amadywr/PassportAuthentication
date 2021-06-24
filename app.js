require('dotenv').config();
const express = require("express");
const expressLayout = require("express-ejs-layouts");
const mongoose = require("mongoose");
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");

const app = express();

//Passport config
require("./config/passport")(passport);

// Connect to Mongo
mongoose.connect(process.env.MONGOURI, {useNewUrlParser:true, useUnifiedTopology: true})
.then(() => console.log("Mongo connected..."))
.catch(err => console.log(err));

//EJS
app.use(expressLayout);
app.set('view engine', 'ejs');

//BodyParser
app.use(express.urlencoded({extended: false}));

//Express session
app.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true
}));

//Passport middleware
app.use(passport.initialize());
app.use(passport.session());

//connect flash
app.use(flash());

//Global vars
app.use((req, res, next)=>{
    res.locals.success_msg = req.flash("success_msg");
    res.locals.error_msg = req.flash("error_msg");
    res.locals.error = req.flash("error");
    next();
})

//Routes
app.use("/", require("./routes/index"));
app.use("/users", require("./routes/users"));


app.listen(5000, ()=>{
    console.log("server started..");
})