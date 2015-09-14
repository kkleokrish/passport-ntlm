/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    debug = require('debug')('strategy'),
    NTLMSSPMessage = require('./message/ssp/ntlmsspmessage'),
    SMB = require('./message/smb/smb'),
    dns = require('dns');


function NTLMStrategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) {
        throw new TypeError('NTLM Strategy requires a verify callback');
    }

    this._domain = options.domain;
    this._domainDNS = options.domainDNS;
    this._smbServers = [];
    if (this._domainDNS || this._domain) {
        if (!this._domainDNS) {
            this._domainDNS = this._domain.toLowerCase() + '.com';
        }
    }

    if (!options.smbServer) {
        if (this._domainDNS) {
            self = this;
            this._queue = [];
            dns.resolveSrv('_ldap._tcp.dc._msdcs.' + this._domainDNS, function(err, addresses) {
                if (!err) {
                    addresses.forEach(function(address, index, array) {
                        debug('Identified SMB server:' + address.name);
                        self._smbServers.push(address.name);
                    });

                    if (self._smbServers) {
                        self.smbServerLookedUp = true;
                        self._queue.forEach(function(cb) {
                            cb();
                        });
                    } else {
                        throw new TypeError('Error looking up SMB Servers');
                    }
                }
            });
        } else {
            throw new TypeError('NTLM Strategy requires domainDNS, domain or smbServer to be configured');
        }
    } else {
        this._smbServers.push(options.smbServer);
        this.smbServerLookedUp = true;
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
    var authorization = req.headers.authorization;
    if (!authorization) {
        debug('No authorization header. Sending back challenge with NTLM');
        return this.fail(this._challenge());
    } //fail method is added by Passport to the strategy

    var authBuffer = new Buffer(authorization.substring(5), 'base64'); // Remove "NTLM " prefix
    var ntlmSSPMessage = new NTLMSSPMessage(authBuffer);

    debug('Processing Type ' + ntlmSSPMessage.ntlmType);


    var self = this;
    this._processNTLMSSPMessage(ntlmSSPMessage, req, function(username) {
        function verified(err, user, info) {
            if (err) {
                return self.error(err);
            }
            if (!user) {
                return self.fail(info);
            }
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
};

NTLMStrategy.prototype._processNTLMSSPMessage = function(ntlmSSPMessage, req, successCallback) {
    switch (ntlmSSPMessage.ntlmType) {
        case 1:
            this._challengeWithKey(ntlmSSPMessage, req);
            break;
        case 3:
            this._validateUser(ntlmSSPMessage, req, successCallback);
            break;
    }
};

NTLMStrategy.prototype._validateUser = function(ntlmSSPMessage, req, successCallback) {
	var smbStoreId=SMB.buildStoreId(req.socket.remoteAddress, req.socket.remotePort);
    var activeSmb = SMB.store[smbStoreId];
    var self = this;
    console.log("Active SMB: " + activeSmb);
	if (!activeSmb) {
        this.fail(500);
    }
	console.log(" ---- Active SMB: " + activeSmb);
	console.log(util.inspect(req.socket.remoteAddress));
	console.log(util.inspect(req.socket.remotePort));
    activeSmb.authenticate(ntlmSSPMessage.ntlm, ntlmSSPMessage.lm,
        new Buffer(ntlmSSPMessage.username, 'ascii'),
        new Buffer(ntlmSSPMessage.domainName, 'ascii'),
        function(authenticated) {
            self._smbServers.push(activeSmb.smbServer); // Make the SMB server available again
            if (authenticated) {
                successCallback(ntlmSSPMessage.username);
            } else {
                self.fail(401);
            }
        });
};

NTLMStrategy.prototype._challengeWithKey = function(ntlmSSPMessage, req) {

    var self = this;

    function exec() {
	
	//TODO: cache smb against client ip req.ip
        if (self._smbServers) {
            var smbServer = self._smbServers.shift(); //Unqueue the server and make it unavailable until authentication completes
            debug('Using server ' + smbServer);

            var smb = new SMB(smbServer, req.socket.remoteAddress, req.socket.remotePort);
			var smbStoreId=SMB.buildStoreId(req.socket.remoteAddress, req.socket.remotePort);
            smb.getChallenge(function(challenge) {
                SMB.store[smbStoreId] = smb;
				debug('SMB StoreId: ' + smbStoreId);
                debug('SMB Challenge: ' + challenge);
                var type2Message = new NTLMSSPMessage();
                type2Message.buildType2Message(challenge, {
                    domain: self._domain,
                    domainDNS: self._domainDNS
                });
                debug('Sending Type 2 Message: ' + type2Message);
                self.fail('NTLM ' + type2Message.buffer.toString('base64'));
            });
        } else {
            self._queue.push(exec);
        }
    }

    if (this.smbServerLookedUp) {
        exec();
    } else {
        this._queue.push(exec);
    }
};
/**
 * Expose `Strategy`.
 */
module.exports = NTLMStrategy;