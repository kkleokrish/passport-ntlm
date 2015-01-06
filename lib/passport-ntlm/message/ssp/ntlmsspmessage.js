var SecurityBuffer = require('./securitybuffer') 
	, util = require('util');;
function NTLMSSPMessage(ntlmSspBuffer) {
  if (ntlmSspBuffer) { 
    this.signature=ntlmSspBuffer.toString('ascii',0,8);
    this.ntlmType=ntlmSspBuffer.readInt32LE(8);
    switch(this.ntlmType) {
      case 1: 
          this.parseType1Message(ntlmSspBuffer);
          break;
      case 3: 
          this.parseType3Message(ntlmSspBuffer);
        break;
    }
  }
}

NTLMSSPMessage.prototype.parseType1Message= function(ntlmSspBuffer) {
  util.log("Parsing Type 1 message");
  this.flags=ntlmSspBuffer.readInt32LE(12);
  if (this.isNegotiateDomainSupplied()) {
    var suppliedDomainSecurityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(16,24));
    var offset=suppliedDomainSecurityBuffer.dataOffset;
    var dataLength=suppliedDomainSecurityBuffer.dataLength;
    this.domainName=ntlmSspBuffer.slice(offset,offset+dataLength).toString('ascii');

  }
  if (this.isNegotiateWorkStationSupplied()) {
    var suppliedWorkStationBuffer=new SecurityBuffer(ntlmSspBuffer.slice(24,32));
    var offset=suppliedWorkStationBuffer.dataOffset;
    var dataLength=suppliedWorkStationBuffer.dataLength;
    this.workstation=ntlmSspBuffer.slice(offset,offset+dataLength).toString('ascii');
  }

  console.log(this);
}
NTLMSSPMessage.prototype.isNegotiateDomainSupplied=function() {
  return (this.flags & 0x00001000 == 0)?false:true;
}
NTLMSSPMessage.prototype.isNegotiateWorkStationSupplied=function() {
  return (this.flags & 0x00002000 == 0)?false:true;
}      

NTLMSSPMessage.prototype.parseType3Message= function(ntlmSspBuffer) { 
  var securityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(12,20)); //LM/LMV2Response
  var offset=securityBuffer.dataOffset;
  var dataLength=securityBuffer.dataLength;
  this.lm=new Buffer(ntlmSspBuffer.slice(offset,offset+dataLength).toString('hex'),'hex');
  
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(20,28)); //NTLM/NTLMV2Response
  offset=securityBuffer.dataOffset;
  dataLength=securityBuffer.dataLength;
  this.ntlm=new Buffer(ntlmSspBuffer.slice(offset,offset+dataLength).toString('hex'),'hex');        
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(28,36)); //Target Name
  offset=securityBuffer.dataOffset;
  dataLength=securityBuffer.dataLength;
  this.domainName=ntlmSspBuffer.slice(offset,offset+dataLength).toString('ucs2');          
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(36,44)); //User Name
  offset=securityBuffer.dataOffset;
  dataLength=securityBuffer.dataLength;
  this.username=ntlmSspBuffer.slice(offset,offset+dataLength).toString('ucs2'); 
  
  securityBuffer=new SecurityBuffer(ntlmSspBuffer.slice(44,52)); //workstation name
  offset=securityBuffer.dataOffset;
  dataLength=securityBuffer.dataLength;
  this.workstation=ntlmSspBuffer.slice(offset,offset+dataLength).toString('ucs2');                                             
}              


NTLMSSPMessage.buildType2Message= function(challenge) {
  var ntlmSspType2Message=new NTLMSSPMessage();
  //TODO: Hardcoded string. Only challenge portion is dynamic
  var respAuthHex='4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000' +                                                                                  
                    '620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c00530045005200' + 
                    '5600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072' + 
                    '002e0064006f006d00610069006e002e0063006f006d0000000000';
  console.log(respAuthHex);
  ntlmSspType2Message.buffer=new Buffer(respAuthHex,'hex');
  ntlmSspType2Message.buffer.write(challenge.toString('hex'), 24,challenge.length,'hex');
  console.log(ntlmSspType2Message);
  return ntlmSspType2Message;
}                                              

module.exports=NTLMSSPMessage;
