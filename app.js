require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
 
const app = express();
 
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

console.log(process.env.API_KEY);

//---------------------CONNECT TO MONGODB LOCAL SYSTEM------------------------------//

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});

const User = new mongoose.model("User", userSchema);

//---------------------ROUTE GET: RENDER THE PAGE------------------------------//

app.get("/", function(req, res){
    res.render("home");
})
 
app.get("/login", function(req, res){
    res.render("login");
})

app.get("/register", function(req, res){
    res.render("register");
})

//---------------------ROUTE POST: REGISTER NEW ACCOUNNT------------------------------//

app.post("/register", function(req, res){

    //create password with salt and hashing 10 times by bcrypt
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save(function(err){
            if(!err){
                res.render("secrets")
            }
        })
    });

})

//---------------------ROUTE POST: LOGIN------------------------------//

app.post("/login", function(req, res){

    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                //check the password if the sama hashing as one in the database
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result == true){
                        res.render("secrets");
                    }
                });      
            }
        }
    });

});


 
app.listen(3000, function() {
    console.log("Server started on port 3000.");
});
