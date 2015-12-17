  // ========== Lurch vars ==========
  var lurch = {};
  lurch.auth = {};
  lurch.auth.github_token = '';
  lurch.auth.github_user = '';

  // ========== Passport Libs ==========
  var passport = require("passport");
  var LocalStrategy = require("passport-local").Strategy;
  var bodyParser = require('body-parser');
  var crypto = require('crypto');

  // ========== Express Config ==========
  var port = Number(process.env.PORT || 5000);
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
  app.get('/auth/github/revoke', function(req, res){
    org.revokeToken({token: lurch.auth.sfdc_token}, function(err, resp) {
      lurch.auth.sfdc_token = '';
      res.redirect('/index.html');
    });
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
    //or an issue comment and is from the Cumulus org lurch: review is added
    //add the pull request
    if (event_name === 'pull_request' || event_name == 'issue_comment'){
        //add the checklist if appropriate

        //set the tracking id to search for existing connected AA issues
        var tracking_id = '';
        var issue_number = '';
        var gh_url = '';
        var issue_body = '';
        var issue_action = event_body.action;
        var comment_body = '';
        switch (event_name){
          case 'issue_comment':
            issue_number = event_body.issue.number;
            gh_url = event_body.issue.html_url;
            tracking_id = event_body.issue.id;
            comment_body = event_body.comment.body;
            issue_body = event_body.issue.body;
          break;
          case 'pull_request':
            issue_number = event_body.pull_request.number;
            gh_url = event_body.pull_request.html_url;
            tracking_id = event_body.pull_request.id;
            issue_body = event_body.issue.body;
          break;
        }

        var lurchcommand = '';
        //if there's a lurch command, get it
        var command_string = event_name === 'issue_comment' ? event_body.comment.body : event_body.issue.body;
        if (command_string.indexOf('**lurch:') > -1){
          var command = command_string.substring(command_string.indexOf('**lurch:'), command_string.length);
          lurchcommand = command.replace('**lurch:', '').trim();
          console.log('LURCH COMMAND: ' + lurchcommand);
          if (lurchcommand.toLowerCase().indexOf('review') > -1){

            //determine what other sections should be added
            var ghcomment = {
              user: event_body.sender.login,
              repo: event_body.repository.full_name,
              number: issue_number,
              body: "\n#### General\n- [ ] All new pages, classes or metadata conform to naming conventions\n"
            };

            if (lurchcommand.toLowerCase().indexOf('apex') > -1){
              ghcomment.body += "\n#### Apex\n- [ ] This request includes Apex\n	- [ ] Sharing/Without/None has been explicitly determined and explained\n	- [ ] FLS is appropriately checked and enforced\n- [ ] Custom settings access is done through appropriate interfaces\n- [ ] Methods are appropriately sized and scopes\n- [ ] Inner classes utilized where appropriate\n- [ ] Dependencies are done explicitly or have been noted where dynamic\n- [ ] API Version is explicitly set to the latest or otherwise indicated as to why not\n- [ ] Code is bulkified\n	- [ ] No SOQL or DML in For loops\n	- [ ] Async calls in For loops are properly rate limited\n	- [ ] Code utilized DML wrapper where appropriate\n- [ ] No new triggers have been added\n- [ ] All currency operations are multi-currency capable and compliant\n- [ ] Any new triggered functionality properly implements TDTM interface\n	- [ ] A new TDTM record has been added to the install script for this class\n	- [ ] Trigger recursion is handled appropriately\n- [ ] All SOQL queries have been written as selectively as possible, and limited where appropriate\n- [ ] Code is properly wrapped in try-catch and exceptions handled through the error handling framework\n- [ ] This request includes batch or queueable apex\n	- [ ] Batch apex is appropriately daisy-chained where required\n- [ ] This request includes scheduable jobs\n	- [ ] Scheduable jobs are properly injected into the scheduable framework\n";
              ghcomment.body += "\n#### Tests\n- [ ] Test coverage is > 85%\n- [ ] Tests are in separate test classes\n- [ ] Test conform to naming conventions\n- [ ] All tests have positive and negative assertions\n- [ ] Test data properly stands-up TDTM records where needed\n- [ ] Tests make use of StartTest() and StopTest()\n- [ ] Tests leverage different users and profiles\n";
            }
            if (lurchcommand.toLowerCase().indexOf('visualforce') > -1)
              ghcomment.body += "\n#### Visualforce\n- [ ] This request includes VisualForce\n	- [ ] Request meets mobile requirements\n	- [ ] All pages are 508 compliant\n	- [ ] All labels and text are translatable via Custom Labels\n	- [ ] This VF has a controller\n		- [ ] Controller sharing has been determined\n		- [ ] Parameters are properly escaped\n- [ ] CSRF protections are in place\n- [ ] FLS is appropriately checked and enforced\n- [ ] Business logic is not included in the controller\n- [ ] Controller uses bind variables in SOQL\n- [ ] Viewstate is managed through use of transients, etc.\n	- [ ] Page includes custom CSS\n	- [ ] Page include custom JS\n		- [ ] Page includes new libraries or library requirements\n		- [ ] Libraries are zipped and hosted in Static Resources\n- [ ] Visualforce page utilizes existing VF components\n- [ ] Templates are used where appropriate\n- [ ] Visualforce page is an embedded component or page\n- [ ] Visualforce page accepts user parameters for extendability\n- [ ] User parameters are properly escaped and cleaned\n";

            if (lurchcommand.toLowerCase().indexOf('lightning') > -1)
              ghcomment.body += "\n#### Lightning";

            github.issues.createComment(ghcomment, function(err, res){
              if (!err) console.log('Posted back to Github');
              else console.log(err);
            });
          }//indexOf('review')
        }//indexOf('**lurch')
    }//close if pull_request || issue_comment
  };//close lurch.processGithubEvent
