var SecurityBuffer = require('./securitybuffer') 
	, util = require('util');;
function NTLMSSPMessage(ntlmSspBuffer) {
  if (ntlmSspBuffer) { 
    this.signature=ntlmSspBuffer.toString('ascii',0,8);
    this.ntlmType=ntlmSspBuffer.readInt32LE(8);
    switch(this.ntlmType) {
      case 1: 
          this._parseType1Message(ntlmSspBuffer);
          break;
      case 3: 
          this._parseType3Message(ntlmSspBuffer);
        break;
    }
  } else {
	this.signature='NTLMSSP';
  }
}

NTLMSSPMessage.prototype._parseType1Message= function(ntlmSspBuffer) {
  util.log("Parsing Type 1 message");
  util.debug("Type 1 message: " + ntlmSspBuffer.toString('hex'));
  this.flags=ntlmSspBuffer.readInt32LE(12);
  if (this.isNegotiateDomainSupplied()) {
    var suppliedDomainSecurityBuffer=new SecurityBuffer(ntlmSspBuffer,16);
    this.domainName=suppliedDomainSecurityBuffer.extractData();

  }
  if (this.isNegotiateWorkStationSupplied()) {
    var suppliedWorkStationBuffer=new SecurityBuffer(ntlmSspBuffer,24);
    this.workstation=suppliedWorkStationBuffer.extractData();
  }

  util.debug(this);
}

NTLMSSPMessage.prototype._parseType2Message= function(ntlmSspBuffer) {
  util.log("Parsing Type 2 message");
  util.debug("Type 2 message: " + ntlmSspBuffer.toString('hex'));
  
  this.signature=ntlmSspBuffer.toString('ascii',0,8);
  this.ntlmType=ntlmSspBuffer.readInt32LE(8);
  var targetNameSecurityBuffer=new SecurityBuffer(ntlmSspBuffer,12);
  this.targetName=targetNameSecurityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);  
  
  this.flags=ntlmSspBuffer.readInt32LE(20);
  this.challenge=new Buffer(ntlmSspBuffer.slice(24,32).toString('hex'), 'hex');
  
  this.context=new Buffer(ntlmSspBuffer.slice(32,40).toString('hex'), 'hex');
  
  var targetInformationBuffer=new SecurityBuffer(ntlmSspBuffer,40);
  this.targetInformation={};
  var targetInfoBuffer=targetInformationBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);
  util.debug('Length of target information: ' + targetInformationBuffer.dataLength);
  
  var targetInformationBlockLength=targetInfoBuffer.length;
  var offset=0;
  
  while(offset < targetInformationBlockLength) {
	var targetInformation={};
	
	targetInformation.type=targetInfoBuffer.readUInt16LE(offset);
	offset+=2;
    targetInformation.length=targetInfoBuffer.readUInt16LE(offset);
	offset+=2;
    var subbuffer=targetInfoBuffer.slice(offset,offset+targetInformation.length);
	offset+=targetInformation.length;
	targetInformation.content=subbuffer.toString('ucs2');
	
	switch (targetInformation.type) {
		case 1: 
			this.targetInformation.server=targetInformation.content;
			break;
		case 2:
			this.targetInformation.domain=targetInformation.content;
			break;
		case 3:
			this.targetInformation.serverDNS=targetInformation.content;
			break;
		case 4:
			this.targetInformation.domainDNS=targetInformation.content;
			break;		
		default:
			//Ignore
			break;
	}
  }
  
  console.log(this);
}

NTLMSSPMessage.prototype.isNegotiateDomainSupplied=function() {
  return (this.flags & 0x00001000 == 0)?false:true;
}
NTLMSSPMessage.prototype.isNegotiateWorkStationSupplied=function() {
  return (this.flags & 0x00002000 == 0)?false:true;
}      

NTLMSSPMessage.prototype._parseType3Message= function(ntlmSspBuffer) { 
  util.debug("Type 3 message: " + ntlmSspBuffer.toString('hex'));
  
  var securityBuffer=new SecurityBuffer(ntlmSspBuffer,12); //LM/LMV2Response
  this.lm=securityBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);
  
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer,20); //NTLM/NTLMV2Response
  this.ntlm=securityBuffer.extractData(SecurityBuffer.DATATYPE.BUFFER);        
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer,28); //Target Name
  this.domainName=securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);          
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer,36); //User Name
  this.username=securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2);  
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer,44); //workstation name
  this.workstation=securityBuffer.extractData(SecurityBuffer.DATATYPE.UCS2); 
  util.debug(this);  
}              


NTLMSSPMessage.prototype.buildType2Message= function(challenge, targetServerInformation) {
  this.ntlmType=2;
  this.flags=0x00810201;	
  this.challenge=challenge;
  this.targetInformation={};
  if (targetServerInformation) {
	if (targetServerInformation.server)  {
		this.targetInformation.server=targetServerInformation.server;
	}
	
	if (targetServerInformation.domain)  {
		this.targetInformation.domain=targetServerInformation.domain;
	}	
	
	if (targetServerInformation.serverDNS)  {
		this.targetInformation.serverDNS=targetServerInformation.serverDNS;
	}
	
	if (targetServerInformation.domainDNS)  {
		this.targetInformation.domainDNS=targetServerInformation.domainDNS;
	}	
  }
  this.context=[0,0];
  //TODO: Hardcoded string. Only challenge portion is dynamic
  var respAuthHex='4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000' +
                    '620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c00530045005200' + 
                    '5600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072' + 
                    '002e0064006f006d00610069006e002e0063006f006d0000000000';
  console.log(respAuthHex);
  ntlmSspType2Message.buffer=new Buffer(respAuthHex,'hex');
  ntlmSspType2Message.buffer.write(challenge.toString('hex'), 24,challenge.length,'hex');
  util.debug("Type 2 message: " + ntlmSspType2Message.buffer.toString('hex'));
  return ntlmSspType2Message;
}                                              

module.exports=NTLMSSPMessage;
