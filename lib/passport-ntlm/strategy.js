/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
    , util = require('util');
	
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('NTLM Strategy requires a verify callback'); }
  
  this._domain = options.domain;
  if (! this._domain ) {
	if (!options.smbServer) { throw new TypeError('NTLM Strategy requires domain or smbServer to be configured'); }
	this._smbServer=options._smbServer;
  }
  passport.Strategy.call(this);
  this.name = 'ntlm';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate using windows SSO.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  

  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  try {
    if (self._passReqToCallback) {
      this._verify(req, username, verified);
    } else {
      this._verify(username, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};