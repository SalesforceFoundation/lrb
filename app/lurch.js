window.onload = function(){

  $("[id$='nav_option']").on('click', function() {
    //deactive all selected menu items
    $("[id$='nav_option']").parent().removeClass('active');
    //check the clicked one
    $(this).parent().addClass('active');
  });

  $(".github-connect").on('click', function(){
    window.location.replace("./auth/github");
  });
  $(".github-disconnect").on('click', function(){
    window.location.replace("./auth/github/revoke");
  });
  $("[id='logout_lurch']").on('click', function() {
    window.location.replace("./logout");
  });

  $.ajax('/auth/github/status', {
   type: 'GET',
   dataType: 'text',
   success: function(data) {
     var res = JSON.parse(data);
     if (res.status === true){
       $(".gh-auth-remove").hide();
       $(".github-connect").hide();
       $(".gh-auth-ok").show();
       $(".github-disconnect").show();
    }else{
      $(".gh-auth-remove").show();
      $(".github-connect").show();
      $(".gh-auth-ok").hide();
      $(".github-disconnect").hide();
    }
  },
   error: function(err){ console.log('Error retrieving statuses: ' + err);}
  });

  io.connectToServer = function ( data ) {
    //connect socket
    io.socket = io.connect('/', {data: data});
    io.socket.on('error', function (err){
      console.log('Connection error: ' + err);
    });
    //on a successful connection, set all of our other event handlers
    io.socket.on('onconnected', function( data ) {
      io.socket.on('logout_client', function () {
        console.log('User logout requested');
        window.location.replace("/logout");
      });
    });
  };
  io.connectToServer();
};
