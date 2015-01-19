# Passport-NTLM

NTLM (a.k.a Windows SSO) authentication strategy for [Passport](https://github.com/jaredhanson/passport).

This module lets you authenticate HTTP requests using Integrated Windows 
Authentication in your Node.js applications. Currently it implements 
only NTLM based authentication. By plugging into Passport, support for 
this scheme can be easily and unobtrusively integrated into any 
application or framework that supports 
[Connect](http://www.senchalabs.org/connect/)-style middleware, 
including [Express](http://expressjs.com/). 



The authentication mechanism involves the application requesting the 
credentials of the currently logged in Windows domain user, encrypted 
using the key obtained from one of the domain controllers and passing it 
on to the domain controller for validation. In this mechanism the 
application receives only the encrypted password of the user, encrypted 
using a key generated by the domain controller, that is valid only for 
one authentication session with the domain controller. 



The module works by obtaining encryption key (session key) from the 
domain controller and challenging the client browser with the key to 
receive the encrypted credentials and clear text user name, which is 
then passed along to the domain controller. 



## Install

    $ npm install passport-ntlm

## Usage of NTLM

### Configure Strategy

The NTLM authentication strategy authenticates using the credentials 
sent by the browser automatically, in response to the NTLM challenge. 
The strategy requires an `options` object and a `verify` callback. The 
`options` must include one of `domainDNS`, `domain` or `smbServer`, 
which will be used to identify the server to validate the credentials. 
The `verify` callback must accept the username and call `done` 
provinding a user. 

        var NTLMStrategy = require('passport-ntlm').Strategy
		passport.use(new NTLMStrategy({domain:'WINDOWSDOMAIN'},
		  function(username, done) {
			var user={ username: username };
			  return done(null, user);
		  }
		));	  
		
Use `passport.authenticate()`, specifying the `'ntlm'` strategy, to 
authenticate requests. Since NTLM authentication requests make multiple 
exchanges and require the corresponding SMB session to be active till 
the authentication is complete session support is needed. 
 
For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/private', 
      passport.authenticate('ntlm', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

## Credits

  - [Krishnakumar Natarajan](http://github.com/kkleokrish)

## License

[The MIT License](http://opensource.org/licenses/MIT)