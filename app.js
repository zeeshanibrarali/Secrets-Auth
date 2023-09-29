require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://127.0.0.1:27017/UserDB", {useNewUrlParser: true});

const userSchema =  new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// for the use of encryption of the data using key.

// const encrypt = require("mongoose-encryption");
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

// for the third level of security
// const md5 = require("md5");
//  password: md5(req.body.password); both in login and register 

// for the fourth level of security
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// app.post("/register", function(req, res){

//     bcrypt.hash(req.body.password, saltRounds) 
//     .then((hash)=>{
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
    
//         newUser.save()
//         .then(() =>{
//             res.render("secrets");
//         })
//         .catch((err) => {
//             console.log(err);
//         }) 
//     })
//     .catch((err) =>{
//         console.log(err);
//     })
    
// });

// app.post("/login", function(req, res){
//     const email = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: email})
//     .then((foundUser) =>{
//         bcrypt.compare(password, foundUser.password)
//         .then((result)=>{
//             if(result === true){
//                 res.render("secrets");
//             }
//         })
//         .catch((err) =>{
//             console.log(err);
//         })
//     })
//     .catch((err) =>{
//         console.log(err);
//     })
// })

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
    done(null, user.id);
});
  
passport.deserializeUser((id, done) => {
    User.findById(id)
    .then(user => {
        done(null, user);
    })
    .catch(err => {
        done(err, null);
    });
});

// Google open Authentication

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secret.
    res.redirect("/secrets");
  });

app.get("/", function(req, res){
    res.render("home");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        console.log(err);
    });
    res.redirect("/");
});

app.get("/secrets", function(req, res){
    User.find({secret:{$ne: null}})
    .then((foundUsers)=>{
        if(foundUsers){
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    })
    .catch((err)=>{
        console.log(err);
    })
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id)
    .then((foundUser) =>{
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save()
            .then(()=>{
                res.redirect("/secrets");
            });
        }
    })
    .catch((err)=>{
        console.log(err);
    });
    
});


app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res ,function(){
                res.redirect("/secrets");
            }); 
        }
    });   
});

// app.post("/login", function(req, res){

//     const newUser = new User({
//         email: req.body.username,
//         password: req.body.password
//     });

//     req.login(newUser, function(err){
//         if(err){
//             console.log(err);
//         }else{
//             passport.authenticate("local")(req, res ,function(){
//                 res.redirect("/secrets");
//             }); 
//         };
//     });
    
// });

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

app.listen(3000, function(){
    console.log("Server started at port 3000");
})



// incorporate sign in with google and facebook.