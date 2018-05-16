var createError = require('http-errors');
var express = require('express');
var request = require('request');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var flash = require('flash');
var session = require('express-session');
var passport = require('passport');
var OidcStrategy = require('passport-openidconnect').Strategy;

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'werfghnjmlpouhyf',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 60000 }
}));
app.use(flash());


// use passport session
app.use(passport.initialize());
app.use(passport.session());

// set up passport
passport.use('oidc', new OidcStrategy({
  issuer: 'https://dev-846291.oktapreview.com/oauth2/default',
  authorizationURL: 'https://dev-846291.oktapreview.com/oauth2/default/v1/authorize',
  tokenURL: 'https://dev-846291.oktapreview.com/oauth2/default/v1/token',
  userInfoURL: 'https://dev-846291.oktapreview.com/oauth2/default/v1/userinfo',
  clientID: '0oaf1pgbxb57crsxr0h7',
  clientSecret: 'te0cHOYl-MqyilntFc478XFtYCGkbZ2lWheM-GH2',
  callbackURL: 'http://localhost:3000/authorization-code/callback',
  scope: 'openid profile'
}, (issuer, sub, profile, accessToken, refreshToken, done) => {
  return done(null, profile);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
})

app.use('/', indexRouter);
app.use('/users', usersRouter);

function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login')
}

app.use('/profile', ensureLoggedIn, (req, res) => {
  res.render('profile', { title: 'Express', user: req.user });
});

app.use('/login', passport.authenticate('oidc'));

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
