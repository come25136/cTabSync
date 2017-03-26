const
  config = require('config'),
  fs = require('fs'),
  https = require('https'),
  express = require('express'),
  app = express(),
  session = require('express-session'),
  ejs = require('ejs'),
  cookieParser = require('cookie-parser'),
  passport = require('passport'),
  TwitterStrategy = require('passport-twitter').Strategy,
  sslserver = https.createServer(
    {
      key: fs.readFileSync(config.get('certs.key')),
      cert: fs.readFileSync(config.get('certs.cert'))
    }, app)
    .listen(process.env.PORT || 3000, function () {
      console.log(`${config.get('server.name')} server | port: ${this.address().port}`);
    }),
  io = require('socket.io').listen(sslserver);

app.engine('ejs', ejs.renderFile);
app.use(express.static('views'));
app.use(cookieParser());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: config.get('server.secret')
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) { done(null, user); });
passport.deserializeUser(function (user, done) { done(null, user); });

passport.use(new TwitterStrategy({
  consumerKey: config.get('api-keys.twitter.ck'),
  consumerSecret: config.get('api-keys.twitter.cs'),
  callbackURL: `https://${config.get('server.domain')}/auth/twitter/callback`
},
  function (token, tokenSecret, profile, done) {
    done(null, profile['_json']['screen_name']);
  }
));

app.get('/auth/twitter', passport.authenticate('twitter'));

app.get('/auth/twitter/callback',
  passport.authenticate('twitter', {
    successRedirect: '/',
    failureRedirect: '/'
  })
);

app.get('/',
  function (req, res) {
    if (!req.user) {
      res.redirect("/auth/twitter");
    } else {
      res.render('index.ejs', {
        domain: config.get('server.domain'),
        user: req.user
      });
    }
  }
);

var tabs = {}, userHash = {};

io.sockets.on('connection', function (socket) {
  socket.emit('connect');

  socket.on('connected', function (data) {
    if (data.name) {
      userHash[socket.id] = { 'name': data.name };
      socket.join(data.name);

      if (tabs[userHash[socket.id]['name']]) socket.emit('push', { 'tabs': tabs[userHash[socket.id]['name']] });
      if (data.tabs) tabs[userHash[socket.id]['name']] = data.tabs;
    } else {
      socket.disconnect();
    }
  });

  socket.on('push', function (data) {
    if (userHash[socket.id]['name']) {
      io.to(userHash[socket.id]['name']).emit('push', { 'tabs': data.tabs });
      tabs[userHash[socket.id]['name']] = data.tabs;
    } else {
      socket.emit('connect');
    }
  });
});
