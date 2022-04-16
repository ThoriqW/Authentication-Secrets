require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const FacebookStrategy = require("passport-facebook").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

//set up session
app.use(session({
    secret: "kodeRahasia",
    resave: false,
    saveUninitialized: true
}))

//initialize passport and initalize passport for can manage session
app.use(passport.initialize());
app.use(passport.session());

//Connect to mongoDB local System
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: Array
});

//Create plugin passportLocalMongoose for userSchema 
userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//Crate a local strategy to authenticate the users using their username and password
passport.use(User.createStrategy());

//this is using for create a session, serializerUser for create a cookies and deserializerUser for end or crumble the cookies  
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

//create user or login using google account
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {

        console.log(profile);

        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

//create user or login with facebook account
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        profileFields: ['id', 'displayName', 'photos', 'email']
    },
    function (accessToken, refreshToken, profile, cb) {

        console.log(profile);

        User.findOrCreate({
            facebookId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


//Route GET
app.get("/", function (req, res) {
    res.render("home");
});

//Authenticate google account
app.get("/auth/google",
    passport.authenticate('google', {
        scope: ['profile']
    })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: "/login"
    }),
    function (req, res) {
        // Successful authentication, redirect secrets page.
        res.redirect("/secrets");
    }
);

//Authenticate facebook account
app.get('/auth/facebook', 
    passport.authenticate('facebook', {
    scope: ["email"]
    })
);

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect secrets page.
        res.redirect('/secrets');
    }
);

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({"secrets" : {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        } else {
            res.render("secrets", {userHaveSecret : foundUsers});
        }
    });
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/login")
    }
});

//create a secret text with the current user login and add into the the file user. 
app.post("/submit", function(req, res){
    const submittedUserSecret = req.body.secret;

    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if(foundUser) {
                console.log(foundUser)
                foundUser.secrets.push(submittedUserSecret);
                foundUser.save(function(err){
                    if(err){
                        console.log(err);
                    } else {
                        res.redirect("/secrets");
                    }
                });
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/")
});


//Route POST : Register 
app.post("/register", function (req, res) {

    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err)
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })

})


//Route POST : Login
app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err)
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});



app.listen(3000, function () {
    console.log("Server started on port 3000.");
});
