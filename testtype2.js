var sample="4e544c4d53535000020000000600060030000000010281000001020304050607000000000000000020002000360000006300740073000200060063007400730004000e006300740073002e0063006f006d0000000000";
var NTLMSSPMessage=require('./lib/passport-ntlm/message/ssp/ntlmsspmessage');
var challenge=new Buffer("0001020304050607","hex");
var type2=new NTLMSSPMessage();
var samples=[];

var count=100;
for (var i=1; i<= count; i++) {
	type2.buildType2Message(challenge, {
                    domain: "cts",
                    domainDNS: "cts.com"
                });
	samples.push(type2.buffer.toString("hex"));
}
var goodcount=0;
var badcount=0;
for (var i=0; i< samples.length; i++) { 
	if (samples[i] === sample) {
		console.log("Good");
		goodcount++;
	} else {
		console.log("Bad :" + samples[i]);
		badcount++;
	}
}

console.log("Summary");
console.log("Good: "  + goodcount);
console.log("Bad: "  + badcount);