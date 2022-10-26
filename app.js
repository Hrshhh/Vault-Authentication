require('dotenv').config()
const express = require('express');
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const encrypt = require('mongoose-encryption');
const md5 = require("md5");
const bcrypt = require("bcrypt");
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const saltRounds = 10;

const app = express();

// console.log(process.env.SECRET);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(session({
    secret: "Bantaibacchi bamai.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB",()=>{
    console.log("Connected to the database")
})

const userSchema = new mongoose.Schema({
    email: {
        type: String
    },
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
})

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_SECRET_KEY,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
    });

app.get("/register", (req, res) => {
    res.render("register")
})

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/secrets", function(req, res){
    User.find({"secrets": {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers})
            }
        }
    })
})

app.get("/logout", function(req,res){
    req.logout((err) => {
        if(err){
            return next(err);
        }
    });
    res.redirect("/");
})

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()){
        res.render("submit")
    }
    else{
        res.redirect("/login")
    }
})

app.post("/submit", (req, res)=> {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        }
    })
})

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err)
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets");
            })
        }
    })





    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     })
    
    //     newUser.save((err) => {
    //     S    if(err){
    //             console.log(err);
    //         }
    //         else{
    //             res.render("secrets");
    //         }
    //     })
    // });
    
})

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
    



    // const username = req.body.username;
    // const password = req.body.password;
    // User.findOne({email: username}, (err, result)=> {
    //     if(err){
    //         console.log(err);
    //     }
    //     else{
    //         if(result){
    //             bcrypt.compare(password, result.password, function(err, ressu) {
    //                 if(ressu === true){
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
            
    //     }
    // });

})

app.listen(3000, () => {
    console.log("Connected successfully")
})