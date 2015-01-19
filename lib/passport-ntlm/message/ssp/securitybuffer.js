// Constructor
function SecurityBuffer(messageBuffer, start) {
    if (messageBuffer) {
        var subbuffer = messageBuffer.slice(start, start + 8); // Security Buffer is 8 bytes long.
        this.dataLength = subbuffer.readUInt16LE(0);
        this.dataOffset = subbuffer.readUInt32LE(4);
        this.dataBuffer = messageBuffer.slice(this.dataOffset, this.dataOffset + this.dataLength);
    } else {
        this._buffer = new Buffer(8);
    }
}

SecurityBuffer.DATATYPE = Object.freeze({
    ASCII: 0,
    UCS2: 1,
    BUFFER: 2
});
SecurityBuffer.prototype.extractData = function(dataType) {
    if (!dataType) dataType = SecurityBuffer.DATATYPE.ASCII;
    var subbuffer = this.dataBuffer;
    switch (dataType) {
        case SecurityBuffer.DATATYPE.ASCII:
            return subbuffer.toString('ascii');
        case SecurityBuffer.DATATYPE.UCS2:
            return subbuffer.toString('ucs2');
        case SecurityBuffer.DATATYPE.BUFFER:
            return new Buffer(subbuffer.toString('hex'), 'hex');
        default:
            throw new TypeError('Datatype has to be one of SecurityBuffer.DATATYPE.ASCII or SecurityBuffer.DATATYPE.BUFFER');
    }
};

SecurityBuffer.prototype.toBuffer = function() {
    this._buffer.writeUInt16LE(this.dataLength, 0);
    this._buffer.writeUInt16LE(this.allocatedSpace, 2);
    this._buffer.writeUInt32LE(this.dataOffset, 4);
    return this._buffer;
};

SecurityBuffer.prototype.data = function(datablock, offset) {
    if (typeof datablock == 'object') {
        if (datablock instanceof Buffer) {
            this.dataBuffer = datablock;
        } else {
            this.dataBuffer = new Buffer(datablock); //TODO: Fix encoding etc. Or support only buffer
        }


        this.dataOffset = offset;
        this.dataLength = this.dataBuffer ? this.dataBuffer.length : 0;
        this.allocatedSpace = this.dataLength;
    }
};

// export the class
module.exports = SecurityBuffer;