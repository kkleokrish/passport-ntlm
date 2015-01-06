// Constructor
function SecurityBuffer(dataBuffer) {
  this.dataLength = dataBuffer.readUInt16LE(0);
  this.dataOffset = dataBuffer.readUInt32LE(4);
}
// export the class
module.exports = SecurityBuffer;