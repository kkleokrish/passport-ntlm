/**
 * Module dependencies.
 */
var passport = require('passport')
    , util = require('util')
	, NTLMSSPMessage = require('./message/ssp/ntlmsspmessage')
	, SMB = require('./message/smb/smb')
	, dns=require('dns');
	

function NTLMStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('NTLM Strategy requires a verify callback'); }
  
  this._domain = options.domain;
  
  if (this._domain ) {
	self=this;
	this._queue = [];
	dns.resolveSrv('_ldap._tcp.dc._msdcs.' + this._domain, function (err, addresses) {
		if (! err) {
			addresses.forEach(function (address,index,array) {
				util.debug('Identified SMB server:'  + address.name);
				self._smbServers.push(address.name);
			});
			self.smbServerLookedUp=true;
			self._queue.forEach(function (cb) { cb(); });
		}
	});
  } else {
	if (!options.smbServer) { throw new TypeError('NTLM Strategy requires domain or smbServer to be configured'); }
	this._smbServers=[];
	this._smbServers.push(options.smbServer);
	this.smbServerLookedUp=true;
  }
  passport.Strategy.call(this);
  this.name = 'ntlm';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(NTLMStrategy, passport.Strategy);

/**
 * Authenticate using windows SSO.
 *
 * @param {Object} req
 * @api protected
 */
NTLMStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var authorization = req.headers['authorization'];
  if (!authorization) { 
	util.debug('No authorization header. Sending back challenge with NTLM');
	return this.fail(this._challenge()); 
  } //fail method is added by Passport to the strategy

  var authBuffer=new Buffer(authorization.substring(5), 'base64');// Remove "NTLM " prefix
  var ntlmSSPMessage = new NTLMSSPMessage(authBuffer);
  
  util.debug('Processing Type ' + ntlmSSPMessage.ntlmType);
  
  
  var self = this;
  this._processNTLMSSPMessage(ntlmSSPMessage, req, function (username) {
				  function verified(err, user, info) {
					if (err) { return self.error(err); }
					if (!user) { return self.fail(info); }
					self.success(user, info);
				  }
				  
				  try {
					if (self._passReqToCallback) {
					  self._verify(req, username, verified);
					} else {
					  self._verify(username, verified);
					}
				  } catch (ex) {
					return self.error(ex);
				  }
				});
};

NTLMStrategy.prototype._challenge = function() {
  return 'NTLM';
}

NTLMStrategy.prototype._processNTLMSSPMessage = function(ntlmSSPMessage, req, successCallback) {
	var session = req.session;
	
	switch(ntlmSSPMessage.ntlmType) {
		case 1:
			this._challengeWithKey(ntlmSSPMessage, req);
			break;
		case 3:
			this._validateUser(ntlmSSPMessage, req, successCallback);
			break;			
	}
}
NTLMStrategy.prototype._validateUser = function(ntlmSSPMessage, req, successCallback) {			  
			  var activeSmb = SMB.store[req.session.challenge];
			  if(!activeSmb) {
				  self.fail(401);
			  }
			  activeSmb.authenticate(ntlmSSPMessage.ntlm, ntlmSSPMessage.lm,
					new Buffer(ntlmSSPMessage.username,'ascii'), 
					new Buffer(ntlmSSPMessage.domainName,'ascii'), 
					function(status){
						console.log(status.toString());
						activeSmb.closeSmbClient();
						SMB.store[req.session.challenge] = undefined;
						req.session.challenge = undefined;
						successCallback(ntlmSSPMessage.username)
					});
}
NTLMStrategy.prototype._challengeWithKey = function(ntlmSSPMessage, req) {
		
		var self=this;
		function exec(){
			if (self._smbServers) {
				var smbServer=self._smbServers.shift();
				self._smbServers.push(smbServer); // Make the SMB server request round robin
				var smb = new SMB(smbServer);
				
				smb.getChallenge(function(challenge){
				  SMB.store[challenge.toString('hex')] = smb;
				  req.session.challenge = challenge.toString('hex');
				  var type2Message = NTLMSSPMessage.buildType2Message(challenge);
				  util.debug('Sending Tpye 2 Message: ' + type2Message);
				  self.fail('NTLM ' + type2Message.buffer.toString('base64'));
				});
			} else {
				self.fail(500);
			}
		}
		
		if(this.smbServerLookedUp){
			exec();
		} else {
			this._queue.push(exec);
		}
}         
/**
 * Expose `Strategy`.
 */
module.exports = NTLMStrategy;