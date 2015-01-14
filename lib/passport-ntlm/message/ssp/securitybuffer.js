// Constructor
function SecurityBuffer(messageBuffer, start) {
	if (messageBuffer) {
		this._messageBuffer=messageBuffer;
		var subbuffer=this._messageBuffer.slice(start, start + 8); // Security Buffer is 8 bytes long.
		this.dataLength = subbuffer.readUInt16LE(0);
		this.dataOffset = subbuffer.readUInt32LE(4);
	} else {
		this._buffer=new Buffer(8);
	}
}

SecurityBuffer.DATATYPE=Object.freeze({ASCII:0, UCS2: 1, BUFFER:2});
SecurityBuffer.prototype.extractData = function (dataType) {
	if (!dataType) dataType=SecurityBuffer.DATATYPE.ASCII;
	var subbuffer=this._messageBuffer.slice(this.dataOffset,this.dataOffset+this.dataLength);
	switch (dataType) {
		case SecurityBuffer.DATATYPE.ASCII:
			return subbuffer.toString('ascii');
			break;
		case SecurityBuffer.DATATYPE.UCS2:
			return subbuffer.toString('ucs2');
			break;			
		case SecurityBuffer.DATATYPE.BUFFER:
			return new Buffer(subbuffer.toString('hex'),'hex');
			break;
		default: 
			throw new TypeError ('Datatype has to be one of SecurityBuffer.DATATYPE.ASCII or SecurityBuffer.DATATYPE.BUFFER');
	}
}

SecurityBuffer.prototype.data = function (datablock, offset) {
	if (typeof datablock == 'object') {
		if (datablock instanceof Buffer) {
			this._dataBuffer=datablock;
		} else {
			this._dataBuffer=new Buffer(datablock);
		}
		
		this.dataOffset=offset;
		this.dataLength=this._dataBuffer?this._dataBuffer.length:0;
		this.allocatedSpace=this.dataLength;
	}
} 

// export the class
module.exports = SecurityBuffer;