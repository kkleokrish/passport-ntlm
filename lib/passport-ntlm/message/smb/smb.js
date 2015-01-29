var net = require('net'),
    debug = require('debug')('smb');

function SMB(smbServer) {
    this._smbServer = smbServer;
}

SMB.protocolBuffer = new Buffer('\xffSMB', 'ascii'); // \xFFSMB - SMB signature
SMB.COMMAND = Object.freeze({
    SMB_COM_NEGOTIATE: 0x72,
    SMB_COM_SESSION_SETUP_ANDX: 0x73
});
SMB.prototype.getChallenge = function(challengeCallback) {
    var negotiateBuffer = this.buildNegotiateMessage();

    var lengthBuffer = new Buffer(4);
    lengthBuffer.writeUInt32BE(negotiateBuffer.length, 0);
    var tcpWrappedMessage = Buffer.concat([new Buffer([0x00]), lengthBuffer.slice(1), negotiateBuffer]);


    debug('SMB_CON_NEGOTIATE: ' + tcpWrappedMessage.toString('hex'));
    var _self = this;
    var _smbClient = net.connect({
        allowHalfOpen: true,
        port: '445',
        host: this._smbServer
    }, function() {
        debug('Connected to ' + _self._smbServer + ':445');
        _smbClient.write(tcpWrappedMessage);
    });
    this.smbClient = _smbClient;
    _smbClient.setKeepAlive(true);
    this.smbClient.once('data', function(data) {
        debug("#####################################\n");
        debug(data.toString('hex'));
        debug(data.slice(73, 81).toString('hex'));
        debug("#####################################\n");
        _self.challenge = data.slice(73, 81);
        challengeCallback(_self.challenge);

    });
    this.smbClient.once('error', function(error) {
        debug(error.stack);
    });

    this.smbClient.on('end', function() {
        debug('client disconnected');
    });
};

SMB.prototype._buildSMBHeader = function(command, smbStatus, options) {
    /*SMB_Header
	{
	UCHAR Protocol[4];
	UCHAR Command;
	SMB_ERROR Status;
	UCHAR Flags;
	USHORT Flags2;
	USHORT PIDHigh;
	UCHAR SecurityFeatures[8];
	USHORT Reserved;
	USHORT TID;
	USHORT PIDLow;
	USHORT UID;
	USHORT MID;
	}
	SMBSTATUS
	{
	UCHAR ErrorClass;
	UCHAR Reserved;
	USHORT ErrorCode;
	}
	*/
    var smbHeaderBuffer = new Buffer(32);
    smbHeaderBuffer.fill(0x00);

    SMB.protocolBuffer.copy(smbHeaderBuffer);
    smbHeaderBuffer.writeUInt8(command, 4);
    if (smbStatus) {
        if (smbStatus.errorClass) {
            smbHeaderBuffer.writeUInt8(smbStatus.errorClass, 5);
        }
        smbHeaderBuffer.writeUInt8(0x00, 6); //Reserved

        if (smbStatus.errorCode) {
            smbHeaderBuffer.writeUInt16LE(smbStatus.errorCode, 7);
        }
    }
    if (options) {
        if (options.flags) {
            smbHeaderBuffer.writeUInt8(options.flags, 9);
        }

        if (options.flags2) {
            smbHeaderBuffer.writeUInt16LE(options.flags2, 10);
        }

        if (options.pidHigh) {
            smbHeaderBuffer.writeUInt16LE(options.pidHigh, 12);
        }

        if (options.securityFeatures) {
            if (options.securityFeatures.length === 8) {
                for (var i = 0; i < 8; i++) {
                    negotiateBuffer.writeUInt8(options.securityFeatures[i], 14 + i);
                }
            }
        }

        if (options.tid) {
            smbHeaderBuffer.writeUInt16LE(options.tid, 24);
        }

        if (options.pidLow) {
            smbHeaderBuffer.writeUInt16LE(options.pidLow, 26);
        }

        if (options.uid) {
            smbHeaderBuffer.writeUInt16LE(options.uid, 28);
        }

        if (options.mid) {
            smbHeaderBuffer.writeUInt16LE(options.mid, 20);
        }
    }
    smbHeaderBuffer.writeUInt16LE(0x00, 22); //Reserved

    return smbHeaderBuffer;
};

SMB.prototype.buildNegotiateMessage = function() {
    var smbHeaderBuffer = this._buildSMBHeader(SMB.COMMAND.SMB_COM_NEGOTIATE);

    var negotiateBuffer = new Buffer(4);

    //Parameters
    negotiateBuffer.writeUInt8(0x00, 0); // No parameters for this messsage
    //Data -[0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00]
    var dialectBuffer = new Buffer(11); //NT LM 0.12 - Only supported dialect
    dialectBuffer.write('NT LM 0.12', 0, undefined, 'ascii');

    negotiateBuffer.writeUInt16LE(dialectBuffer.length + 1, 1);

    negotiateBuffer.writeUInt8(0x02, 3); // Dialect buffer format. Must be 0x02 indicating null-terminated array of characters
    negotiateBuffer = Buffer.concat([smbHeaderBuffer, negotiateBuffer, dialectBuffer]);
    return negotiateBuffer;
};

SMB.prototype.authenticate = function(ntlm, lm, username, domain, callback) {
    var self = this;
    var authBuffer = this.buildAuthMessage(ntlm, lm, username, domain);

    var lengthBuffer = new Buffer(4);
    lengthBuffer.writeUInt32BE(authBuffer.length, 0);
    var tcpWrappedMessage = Buffer.concat([new Buffer([0x00]), lengthBuffer.slice(1), authBuffer]);


    debug('SMB_COM_SESSION_SETUP_ANDX: ' + tcpWrappedMessage.toString('hex'));
    this.smbClient.once('data', function(data) {
        debug("#####################################\n");
        debug("SMB_COM_SESSION_SETUP_ANDX Response");
        debug(data.toString('hex'));
        debug("Extracted Challenge: " + data.slice(73, 81).toString('hex'));
        debug("#####################################\n");

        self.closeSmbClient();
        SMB.store[self.challenge] = undefined;
        var status = data.readUInt8(9);
        if (status === 0) { //Authentication successful
            debug("Authentication successful with SMB Server");
            callback(true);
        } else {
            debug("Authentication failed with SMB Server with status code " + status);
            callback(false);
        }

    });

    this.smbClient.once('error', function(error) {
        debug(error.stack);
    });
    this.smbClient.write(tcpWrappedMessage);
};

SMB.prototype.closeSmbClient = function() {
    this.smbClient.destroy();
};

SMB.prototype.buildAuthMessage = function(ntlm, lm, username, domain) {
    var smbHeaderBuffer = this._buildSMBHeader(SMB.COMMAND.SMB_COM_SESSION_SETUP_ANDX);

    var smbParametersBuffer = new Buffer(27); // 1 byte Word count + 26 byte SMB Parameters
    var pos = 0;
    //Do not change the order of writes - notice the pos++
    smbParametersBuffer.writeUInt8(0x0d, pos++); //Word count - 13 words
    //Parameters
    smbParametersBuffer.writeUInt8(0xff, pos++); //AndXCommand
    smbParametersBuffer.writeUInt8(0x00, pos++); //AndXReserved

    smbParametersBuffer.writeUInt16LE(0x00, pos); //AndXOffset
    pos += 2;

    smbParametersBuffer.writeUInt16LE(16644, pos); //MaxBufferSize   
    pos += 2;

    smbParametersBuffer.writeUInt16LE(65535, pos); //MaxMpxCount   
    pos += 2;

    smbParametersBuffer.writeUInt16LE(0, pos); //VcNumber    
    pos += 2;

    smbParametersBuffer.writeUInt32LE(0, pos); //SessionKey    
    pos += 4;

    smbParametersBuffer.writeUInt16LE(lm.length, pos); //OEM Password Length  
    pos += 2;

    smbParametersBuffer.writeUInt16LE(ntlm.length, pos); //Unicode Password Length
    pos += 2;

    smbParametersBuffer.writeUInt32LE(0x00, pos); //Reserved
    pos += 4;

    smbParametersBuffer.writeUInt32LE(0x00, pos); //Capabilities
    pos += 4;

    //Data
    var dataBuffer = Buffer.concat([lm, ntlm, username, new Buffer([0x00]), domain, new Buffer([0x00]),
        new Buffer('Windows NT 1381', 'ascii'), new Buffer([0x00]), new Buffer('Windows NT 4.0', 'ascii'), new Buffer([0x00])
    ]);
    var dataBufferWithLength = new Buffer(dataBuffer.length + 2);

    dataBufferWithLength.writeUInt16LE(dataBuffer.length, 0);
    dataBuffer.copy(dataBufferWithLength, 2);
    var smbAuthBuffer = Buffer.concat([smbHeaderBuffer, smbParametersBuffer, dataBufferWithLength]);
    return smbAuthBuffer;
};

SMB.store = {

};

module.exports = SMB;