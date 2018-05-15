var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
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
  cookie: { secure: true }
}))
// use passport session
app.use(passport.initialize());
app.use(passport.session());
  
// set up passport
passport.use(new OidcStrategy({
  issuer: 'https://dev-846291.oktapreview.com/oauth2/default',
  authorizationURL: 'https://dev-846291.oktapreview.com/oauth2/default/v1/authorize',
  tokenURL: 'https://dev-846291.oktapreview.com/oauth2/default/v1/token',
  clientID: '0oaf1pgbxb57crsxr0h7',
  clientSecret: 'te0cHOYl-MqyilntFc478XFtYCGkbZ2lWheM-GH2',
  callbackURL: 'http://localhost:3000/authorization-code/callback',
  scope: 'openid profile'
},
function(){}))

app.use('/', indexRouter);
app.use('/users', usersRouter);

app.get('/auth/example', passport.authenticate('openidconnect'));

app.get('/authorization-code/callback', 
  passport.authenticate('openidconnect', {failureRedirect: '/login/failure'}),
  function(req,res){
    res.redirect('/');
  }
);

app.get('/login/failure', (req,res)=>{
  res.status(500).send("Unable to login");
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
