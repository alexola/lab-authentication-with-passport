const express = require("express");
const router = express.Router();
// User model
const User = require("../models/user");
// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;
const ensureLogin = require("connect-ensure-login");
const passport = require("passport");

router.get("/signup", (req, res, next) => {
    res.render("passport/signup");
});

router.post('/signup', (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    if (username === "" || password === "") {
        res.render('passport/signup', {
            errorMessage: "Field can0t be empty"
        })
        return
    }


    var salt = bcrypt.genSaltSync(bcryptSalt);
    var hashPass = bcrypt.hashSync(password, salt);

    var newUser = User({
        username,
        password: hashPass
    });

    newUser.save((err) => {
        if (err) {
            res.render("passport/signup", {
                errorMessage: "Something went wrong"
            });
        } else {
            res.redirect("/");
        }
    });
});

router.get("/login", (req, res, next) => {
    res.render("passport/login");
});
router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));


router.post('/login', (req, res)=> {
  let username = req.body.username;
  let password = req.body.password;

  if (username === "" || password === "") {
    res.render("passport/login", {
      errorMessage: "Indicate a username and a password to sign up"
    });
    return;
  }

  User.findOne({username: username}, (err, user)=>{
    if(err){
      next(err);
    } else {
      if (!user){
        res.render("passport/login", {
          errorMessage: "Username doesn't exist sign up"
        });
      } else {
        if (bcrypt.compareSync(password, user.password)) {
          req.session.currentUser = user;
          res.redirect("/");
        } else {
          res.render("passport/login", {
            errorMessage: "Incorrect password"
          });
        }
      }
    }
  });

});

router.get("/login", (req, res, next) => {
  res.render("passport/login");
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));
router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});
router.get("/private", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

module.exports = router;
