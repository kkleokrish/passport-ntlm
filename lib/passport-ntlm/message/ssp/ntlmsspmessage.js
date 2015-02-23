var SecurityBuffer = require('./securitybuffer'),
    util = require('util'),
    debug = require('debug')('ntlmsspmessage');

function NTLMSSPMessage(ntlmSspBuffer) {
    if (ntlmSspBuffer) {
        this.signature = ntlmSspBuffer.toString('ascii', 0, 8);
        this.ntlmType = ntlmSspBuffer.readInt32LE(8);
        switch (this.ntlmType) {
            case 1:
                this._parseType1Message(ntlmSspBuffer);
                break;
            case 3:
                this._parseType3Message(ntlmSspBuffer);
                break;
        }
    } else {
        this.signature = 'NTLMSSP';
    }
}

NTLMSSPMessage.prototype._parseType1Message = function(ntlmSspBuffer) {
    util.log("Parsing Type 1 message");
    debug("Type 1 message: " + ntlmSspBuffer.toString('hex'));
    this.flags = ntlmSspBuffer.readInt32LE(12);
    if (this.isNegotiateDomainSupplied()) {
        var suppliedDomainSecurityBuffer = new SecurityBuffer(ntlmSspBuffer, 16);
        this.domainName = suppliedDomainSecurityBuffer.extractData();

    }
    if (this.isNegotiateWorkStationSupplied()) {
        var suppliedWorkStationBuffer = new SecurityBuffer(ntlmSspBuffer, 24);
        this.workstation = suppliedWorkStationBuffer.extractData();
    }

    debug(this);
};

NTLMSSPMessage.prototype._parseType2Message = function(ntlmSspBuffer) {
    util.log("Parsing Type 2 message");
    debug("Type 2 message: " + ntlmSspBuffer.toString('hex'));

    this.signature = ntlmSspBuffer.toString('ascii', 0, 8);
    this.ntlmType = ntlmSspBuffer.readInt32LE(8);
    var targetNameSecurityBuffer = new SecurityBuffer(ntlmSspBuffer, 12);
    this.targetName = targetNameSecurityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);

    this.flags = ntlmSspBuffer.readInt32LE(20);
    this.challenge = new Buffer(ntlmSspBuffer.slice(24, 32).toString('hex'), 'hex');

    this.context = new Buffer(ntlmSspBuffer.slice(32, 40).toString('hex'), 'hex');

    var targetInformationBuffer = new SecurityBuffer(ntlmSspBuffer, 40);
    this.targetInformation = {};
    var targetInfoBuffer = targetInformationBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);
    debug('Length of target information: ' + targetInformationBuffer.dataLength);

    var targetInformationBlockLength = targetInfoBuffer.length;
    var offset = 0;

    while (offset < targetInformationBlockLength) {
        var targetInformation = {};

        targetInformation.type = targetInfoBuffer.readUInt16LE(offset);
        offset += 2;
        targetInformation.length = targetInfoBuffer.readUInt16LE(offset);
        offset += 2;
        var subbuffer = targetInfoBuffer.slice(offset, offset + targetInformation.length);
        offset += targetInformation.length;
        targetInformation.content = subbuffer.toString('ucs2');

        switch (targetInformation.type) {
            case 1:
                this.targetInformation.server = targetInformation.content;
                break;
            case 2:
                this.targetInformation.domain = targetInformation.content;
                break;
            case 3:
                this.targetInformation.serverDNS = targetInformation.content;
                break;
            case 4:
                this.targetInformation.domainDNS = targetInformation.content;
                break;
            default:
                //Ignore
                break;
        }
    }
    debug("Parsed Type 2 Message : ");
    debug(this);
};

NTLMSSPMessage.prototype.isNegotiateDomainSupplied = function() {
    return (this.flags & 0x00001000 === 0) ? false : true;
};

NTLMSSPMessage.prototype.isNegotiateWorkStationSupplied = function() {
    return (this.flags & 0x00002000 === 0) ? false : true;
};

NTLMSSPMessage.prototype._parseType3Message = function(ntlmSspBuffer) {
    debug("Type 3 message: " + ntlmSspBuffer.toString('hex'));

    var securityBuffer = new SecurityBuffer(ntlmSspBuffer, 12); //LM/LMV2Response
    this.lm = securityBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);


    securityBuffer = new SecurityBuffer(ntlmSspBuffer, 20); //NTLM/NTLMV2Response
    this.ntlm = securityBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);

    securityBuffer = new SecurityBuffer(ntlmSspBuffer, 28); //Target Name
    this.domainName = securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);

    securityBuffer = new SecurityBuffer(ntlmSspBuffer, 36); //User Name
    this.username = securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);

    securityBuffer = new SecurityBuffer(ntlmSspBuffer, 44); //workstation name
    this.workstation = securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);
    debug("Parsed Type 3 Message : ");
    debug(this);
};


NTLMSSPMessage.prototype.buildType2Message = function(challenge, targetServerInformation) {
    var targetInformationBuffer, ntlmType2MessagePart1, targetNameSecurityBuffer, serverBuffer,
        targetInformationArray, domainBuffer, serverDNSBuffer, domainDNSBuffer, terminationBuffer,
        targetInformationArrayBuffer, targetInformationSecurityBuffer;
    this.ntlmType = 2;
    this.flags = 0x00810201;
    this.challenge = challenge;
    this.targetInformation = {};
    if (targetServerInformation) {
        if (targetServerInformation.server) {
            this.targetInformation.server = targetServerInformation.server;
        }

        if (targetServerInformation.domain) {
            this.targetInformation.domain = targetServerInformation.domain;
        }

        if (targetServerInformation.serverDNS) {
            this.targetInformation.serverDNS = targetServerInformation.serverDNS;
        }

        if (targetServerInformation.domainDNS) {
            this.targetInformation.domainDNS = targetServerInformation.domainDNS;
        }
    }
    this.context = [0, 0];

    ntlmType2MessagePart1 = new Buffer(48);
    ntlmType2MessagePart1.write(this.signature, 0, null, 'ascii');
    ntlmType2MessagePart1.writeUInt8(0, 7); //Null termination
    ntlmType2MessagePart1.writeUInt32LE(this.ntlmType, 8);

    targetNameSecurityBuffer = new SecurityBuffer();
    targetNameSecurityBuffer.data(new Buffer(this.targetInformation.domain, 'ucs2'), 48);
    targetNameSecurityBuffer.toBuffer().copy(ntlmType2MessagePart1, 12);

    ntlmType2MessagePart1.writeInt32LE(this.flags, 20);
    this.challenge.copy(ntlmType2MessagePart1, 24);

    ntlmType2MessagePart1.writeInt32LE(this.context[0], 32);
    ntlmType2MessagePart1.writeInt32LE(this.context[1], 36);

    targetInformationArray = [];
    if (this.targetInformation.server) {
        serverBuffer = new Buffer(this.targetInformation.server, 'ucs2');
        targetInformationBuffer = new Buffer(4 + serverBuffer.length);
        targetInformationBuffer.writeUInt16LE(1, 0);
        targetInformationBuffer.writeUInt16LE(serverBuffer.length, 2);
        serverBuffer.copy(targetInformationBuffer, 4);
        targetInformationArray.push(targetInformationBuffer);
    }

    if (this.targetInformation.domain) {
        domainBuffer = new Buffer(this.targetInformation.domain, 'ucs2');
        targetInformationBuffer = new Buffer(4 + domainBuffer.length);
        targetInformationBuffer.writeUInt16LE(2, 0);
        targetInformationBuffer.writeUInt16LE(domainBuffer.length, 2);
        domainBuffer.copy(targetInformationBuffer, 4);
        targetInformationArray.push(targetInformationBuffer);
    }

    if (this.targetInformation.serverDNS) {
        serverDNSBuffer = new Buffer(this.targetInformation.serverDNS, 'ucs2');
        targetInformationBuffer = new Buffer(4 + serverDNS.length);
        targetInformationBuffer.writeUInt16LE(3, 0);
        targetInformationBuffer.writeUInt16LE(serverDNS.length, 2);
        serverDNSBuffer.copy(targetInformationBuffer, 4);
        targetInformationArray.push(targetInformationBuffer);
    }

    if (this.targetInformation.domainDNS) {
        domainDNSBuffer = new Buffer(this.targetInformation.domainDNS, 'ucs2');
        targetInformationBuffer = new Buffer(4 + domainDNSBuffer.length);
        targetInformationBuffer.writeUInt16LE(4, 0);
        targetInformationBuffer.writeUInt16LE(domainDNSBuffer.length, 2);
        domainDNSBuffer.copy(targetInformationBuffer, 4);
        targetInformationArray.push(targetInformationBuffer);
    }

    terminationBuffer = new Buffer(4);
    terminationBuffer.writeUInt16LE(0, 0);
    terminationBuffer.writeUInt16LE(0, 2);
    targetInformationArray.push(terminationBuffer);

    targetInformationArrayBuffer = Buffer.concat(targetInformationArray);


    targetInformationSecurityBuffer = new SecurityBuffer();
    targetInformationSecurityBuffer.data(targetInformationArrayBuffer, 48 + targetNameSecurityBuffer.dataLength);

    targetInformationSecurityBuffer.toBuffer().copy(ntlmType2MessagePart1, 40);

    this.buffer = Buffer.concat([ntlmType2MessagePart1, targetNameSecurityBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER), targetInformationArrayBuffer]);

    debug("Type 2 message: " + this.buffer.toString('hex'));
};

module.exports = NTLMSSPMessage;