require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));


mongoose.connect("mongodb://127.0.0.1:27017/UserDB", {useNewUrlParser: true});

const userSchema =  new mongoose.Schema({
    email: String,
    password: String
});

// for the use of encryption of the data using key.

// const encrypt = require("mongoose-encryption");
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res){
    res.render("home");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/login", function(req, res){
    res.render("login");
});


app.post("/register", function(req, res){

    const newUser = new User({
        email: req.body.username,
        password: md5(req.body.password)
    });

    newUser.save()
    .then(() =>{
        res.render("secrets");
    })
    .catch((err) => {
        console.log(err);
    })
});

app.post("/login", function(req, res){
    const email = req.body.username;
    const password = md5(req.body.password);

    User.findOne({email: email})
    .then((foundUser) =>{
        if(foundUser.password === password){
            res.render("secrets");
        }
    })
    .catch((err) =>{
        console.log(err);
    })
})

app.listen(3000, function(){
    console.log("Server started at port 3000");
})
