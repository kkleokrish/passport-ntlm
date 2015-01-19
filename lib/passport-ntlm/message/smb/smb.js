var net = require('net');

function SMB(smbServer) {
        this._smbServer = smbServer;
    }
    //=================================
    //Mock methods
    /*
    SMB.prototype.getChallenge= function (challengeCallback) {
    	challengeCallback('04de9640d290e23b');
    }

    SMB.prototype.authenticate= function (ntlm,lm,username, domain,callback) {
      callback(0);
    }

    SMB.prototype.closeSmbClient = function() {
      
    };
    */
    //End Mock methods
    //=================================

SMB.prototype.getChallenge = function(challengeCallback) {
    var negotiateBuffer = this.buildNegotiateMessage();

    var lengthBuffer = new Buffer(4);
    lengthBuffer.writeUInt32BE(negotiateBuffer.length, 0);
    var tcpWrappedMessage = Buffer.concat([new Buffer([0x00]), lengthBuffer.slice(1), negotiateBuffer]);


    console.log('SMB_CON_NEGOTIATE: ' + tcpWrappedMessage.toString('hex'));
    var _self = this;
    var _selfSmbClient = net.connect({
        allowHalfOpen: true,
        port: '445',
        host: this._smbServer
    }, function() {
        console.log('Connected to ' + this._smbServer + ':445');
        _selfSmbClient.write(tcpWrappedMessage);
    });
    this.smbClient = _selfSmbClient;
    _selfSmbClient.setKeepAlive(true);
    this.smbClient.once('data', function(data) {
        console.log("#####################################\n");
        console.log(data.toString('hex'));
        console.log(data.slice(73, 81).toString('hex'));
        console.log("#####################################\n");
        // _self.challenge=data.slice(73,81);
        challengeCallback(data.slice(73, 81));

    });
    this.smbClient.once('error', function(error) {
        console.log(error);
        console.log(error.stack);
    });

    this.smbClient.on('end', function() {
        console.log('client disconnected');
    });
};
SMB.prototype.buildNegotiateMessage = function() {
    var negotiateBuffer = new Buffer(4 + 1 + 4 + 1 + 2 + 2 + 8 + 2 + 2 + 2 + 2 + 2 + 1 + 2 + 1);
    var pos = 0;
    negotiateBuffer.writeUInt8(0xff, pos++);
    negotiateBuffer.writeUInt8(0x53, pos++);
    negotiateBuffer.writeUInt8(0x4d, pos++);
    negotiateBuffer.writeUInt8(0x42, pos++);

    negotiateBuffer.writeUInt8(0x72, pos++);
    negotiateBuffer.writeUInt32LE(0x00, pos);
    pos += 4;
    negotiateBuffer.writeUInt8(0x00, pos++);
    negotiateBuffer.writeUInt16LE(0x0000, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    for (var i = 0; i < 8; i++) {
        negotiateBuffer.writeUInt8(0x00, pos++);
    }
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;

    //Parameters
    negotiateBuffer.writeUInt8(0x00, pos++);
    //Data
    var dialectBuffer = new Buffer([0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00]); //NT LM 0.12

    negotiateBuffer.writeUInt16LE(dialectBuffer.length + 1, pos);
    pos += 2;
    negotiateBuffer.writeUInt8(0x02, pos++);
    negotiateBuffer = Buffer.concat([negotiateBuffer, dialectBuffer]);
    return negotiateBuffer;
};

SMB.prototype.authenticate = function(ntlm, lm, username, domain, callback) {
    var authBuffer = this.buildAuthMessage(ntlm, lm, username, domain);

    var lengthBuffer = new Buffer(4);
    lengthBuffer.writeUInt32BE(authBuffer.length, 0);
    var tcpWrappedMessage = Buffer.concat([new Buffer([0x00]), lengthBuffer.slice(1), authBuffer]);


    console.log('SMB_COM_SESSION_SETUP_ANDX: ' + tcpWrappedMessage.toString('hex'));
    this.smbClient.once('data', function(data) {
        console.log("#####################################\n");
        console.log("SMB_COM_SESSION_SETUP_ANDX");
        console.log(data.toString('hex'));
        console.log(data.toString());
        console.log(data.slice(73, 81).toString('hex'));
        console.log("#####################################\n");
        // callback(data.slice(73,81));
        callback(data.readUInt8(9));

    });

    this.smbClient.once('error', function(error) {
        console.log(error);
        console.log(error.stack);
    });
    //TODO: Commented to prevent account lock out
    this.smbClient.write(tcpWrappedMessage);
};

SMB.prototype.closeSmbClient = function() {
    this.smbClient.destroy();
};

SMB.prototype.buildAuthMessage = function(ntlm, lm, username, domain) {
    var negotiateBuffer = new Buffer(4 + 1 + 4 + 1 + 2 + 2 + 8 + 2 + 2 + 2 + 2 + 2 + /*Params*/ 1 + 1 + 1 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 4 + 4 + 2);
    var pos = 0;
    negotiateBuffer.writeUInt8(0xff, pos++);
    negotiateBuffer.writeUInt8(0x53, pos++);
    negotiateBuffer.writeUInt8(0x4d, pos++);
    negotiateBuffer.writeUInt8(0x42, pos++);

    negotiateBuffer.writeUInt8(0x73, pos++);
    negotiateBuffer.writeUInt32LE(0x00, pos);
    pos += 4;
    negotiateBuffer.writeUInt8(0x00, pos++);
    negotiateBuffer.writeUInt16LE(0x0000, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    for (var i = 0; i < 8; i++) {
        negotiateBuffer.writeUInt8(0x00, pos++);
    }
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;
    negotiateBuffer.writeUInt16LE(0x00, pos);
    pos += 2;

    //Parameters
    negotiateBuffer.writeUInt8(0x0d, pos++); //Word count
    negotiateBuffer.writeUInt8(0xff, pos++); //AndXCommand
    negotiateBuffer.writeUInt8(0x00, pos++); //AndXReserved

    negotiateBuffer.writeUInt16LE(0x00, pos); //AndXOffset
    pos += 2;

    negotiateBuffer.writeUInt16LE(16644, pos); //MaxBufferSize   
    pos += 2;

    negotiateBuffer.writeUInt16LE(65535, pos); //MaxMpxCount   
    pos += 2;

    negotiateBuffer.writeUInt16LE(0, pos); //VcNumber    
    pos += 2;

    negotiateBuffer.writeUInt32LE(0, pos); //SessionKey    
    pos += 4;

    negotiateBuffer.writeUInt16LE(lm.length, pos); //OEMPasswordLen    
    pos += 2;

    negotiateBuffer.writeUInt16LE(ntlm.length, pos); //UnicodePasswordLen    
    pos += 2;

    negotiateBuffer.writeUInt32LE(0x00, pos); //Reserved
    pos += 4;

    negotiateBuffer.writeUInt32LE(0x00, pos); //Capabilities
    pos += 4;

    //Data
    var dataBuffer = Buffer.concat([lm, ntlm, username, new Buffer([0x00]), domain, new Buffer([0x00]),
        new Buffer('Windows NT 1381', 'ascii'), new Buffer([0x00]), new Buffer('Windows NT 4.0', 'ascii'), new Buffer([0x00])
    ]);

    negotiateBuffer.writeUInt16LE(dataBuffer.length, pos);
    pos += 2;
    negotiateBuffer = Buffer.concat([negotiateBuffer, dataBuffer]);
    return negotiateBuffer;
};

SMB.store = {

};

module.exports = SMB;