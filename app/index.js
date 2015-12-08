  // ========== Lurch vars ==========
  var lurch = {};
  lurch.auth = {};
  lurch.auth.github_token = '';
  lurch.auth.github_user = '';

  // ========== Nforce and Passport Libs ==========
  var passport = require("passport");
  var LocalStrategy = require("passport-local").Strategy;
  var bodyParser = require('body-parser');
  var crypto = require('crypto');

  // ========== Express Config ==========
  var port = Number(process.env.PORT || 5000);
  var logfmt = require("logfmt");
  var express = require("express");
  var app = express();
  var cookieParser = require('cookie-parser');
  var session = require('express-session');
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());
  app.use(cookieParser());
  app.use(session({ secret: 'yourang?',
                    resave: true,
                    saveUninitialized: true,
                    cookie: { maxAge: 100000000}
                  }));
  app.use(passport.initialize());
  app.use(passport.session());

  // ========== Start server, socket.io and listen for requests ==========
  var http = require('http').Server(app);
  var io = require('socket.io')(http);

  http.listen(port, function(){
    console.log('Listening on port ' + port);
  });

  // ========== Lurch Auth Helper Functions ==========
  lurch.ensureAuthenticated = function(req, res, next) {
    if (req.isAuthenticated() || req.path === '/ghwebhook') {
      return next();
    }
    else{
      res.redirect('/login');
    }
  };

  lurch.checkUserAuth = function (username, password, callback) {
    var r = false;
    if (username === process.env.ADMIN_UN && password === process.env.ADMIN_PW){
      r = true;
    }
    callback(r);
  };

  // ========== node-github Setup ==========
  var OAuth2 = require("oauth").OAuth2;
  var ngithub = require("github");
  var github = new ngithub({
    version: "3.0.0",
    //debug: true,
    protocol: "https",
    host: "api.github.com",
    timeout: 5000,
    headers: {
        "user-agent": "lrb-app"
    }
  });
  var clientId = process.env.GH_CLIENTID;
  var secret = process.env.GH_SECRET;
  var oauth = new OAuth2(clientId, secret, "https://github.com/", "login/oauth/authorize", "login/oauth/access_token");

  // ========== Route Handlers ==========
  app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
  });
  app.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.redirect('/login'); }
      req.logIn(user, function(err) {
        if (err) { return next(err); }
        return res.redirect('index.html');
      });
    })(req, res, next);
  });
  app.get('/login', function(req, res){
    res.sendfile('app/login.html');
  });
  app.use('/', function(req, res, next){
    lurch.ensureAuthenticated(req, res, next);
  });
  app.use('/ghwebhook', function(req, res){
    var gh_sig   = req.headers['x-hub-signature'];
    var gh_event = req.headers['x-github-event'];
    var event_id = req.headers['x-github-delivery'];
    var lurch_gh_sig = '';

    if (!gh_sig || !gh_event || !event_id){
      res.status(400);
      res.send('Missing required header value.');
    }else{
      lurch_gh_sig = 'sha1=' + crypto.createHmac('sha1', process.env.GHWEBHOOK_SECRET).update(JSON.stringify(req.body)).digest('hex');
      if (gh_sig !== lurch_gh_sig){
        res.status(403);
        res.send('Mismatch signature');
      }else{
        lurch.processGithubEvent(gh_event, event_id, req.body);
        res.status(200);
        res.send();
      }
    }
  });

  app.use('/', express.static(__dirname + '/'));

  // ========== Github Authentication ==========
  app.get('/auth/github', function(req,res){
        res.writeHead(303, {
             Location: oauth.getAuthorizeUrl({
               redirect_uri: process.env.APPDOMAIN + "/auth/github/_callback",
               scope: "repo,gist,public_repo,notifications"
             })
         });
         res.end();
  });
  app.get('/auth/github/_callback', function(req, res){
    oauth.getOAuthAccessToken(req.query.code, {}, function (err, access_token, refresh_token) {
        if (err) {
          console.log(err);
          res.writeHead(500);
          res.end(err + "");
          return;
        }
        lurch.auth.github_token = access_token;

        // authenticate github API
        github.authenticate({
          type: "oauth",
          token: lurch.auth.github_token
        });

        //redirect back
        res.writeHead(303, {Location: "/"});
        res.end();
      });
  });
  app.get('/auth/github/status', function(req, res){
    res.writeHead(200, {'Content-Type':'application/json'});
    var status_response = '';
    if (lurch.auth.github_token !== ''){
      status_response = JSON.stringify({'status':true});
    }
    else{
      status_response = JSON.stringify({'status':false});
    }
    res.write(status_response);
    res.end();
  });

  // ========== Lurch Authentication ==========
  passport.serializeUser(function(user, done) {done(null, user);});
  passport.deserializeUser(function(user, done) {done(null, user);});

  passport.use(new LocalStrategy(
    function(username, password, done) {
      lurch.checkUserAuth(username, password, function(result){
        if (result === true){
          console.log("Successful login.");
          var user = username;
          return done(null, user, result);
        } else if (result === false) {
          console.log("Failed login.");
           return done(null, false, { message: 'Incorrect un/pw' });
        } else {
          console.log("Failed, server error");
          return done(err);
        }
      });
    }
  ));

  // ========== Socket.io config ==========
  io.on('connection', function (socket) {
    socket.emit('onconnected', {msg: 'SUP DUDE.'});
    console.log('Client Connected: ' + socket);
  });

  // ========== Lurch Event Processors ==========
  lurch.processGithubEvent = function (event_name, event_id, event_body) {

    //if its a pull request, add the checklist
    if (event_name === 'pull_request'){
        //add the checklist if appropriate
    }
  };
