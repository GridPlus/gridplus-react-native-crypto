const sha256 = require('./sha256.js');
const Buffer = require('buffer/').Buffer;

class ReactNativeCrypto {

  constructor(e) {
    // Hash whatever the entropy provided is and use that hash as the entropy for sjcl
    const shaObj = new sha256('SHA-256', 'TEXT');
    shaObj.update(e);
    this.entropy = shaObj.getHash('HEX');
    this.count = 0;
    this.hash = null;
  }

  get32RandomBytes() {
    const shaObj = new sha256('SHA-256', 'TEXT');
    const r = this.createHash(String(this.count * new Date().getTime()));
    shaObj.update(`${this.entropy}${r}`);
    this.count += 1;
    return shaObj.getHash('HEX');
  }

  // Return 32 bytes of entropy
  generateEntropy () {
    return this.get32RandomBytes();
  }

  // Return n bytes of entropy
  randomBytes (n) {
    const numHashes = Math.ceil(n / 32);
    let b = '';
    for (let i = 0; i < numHashes; i++) {
      b += this.get32RandomBytes();
    }
    return b.slice(0, n*2);
  }

  createHash () {
    this.hash = new Hash();
    return this.hash;
  }
}

class Hash {
  constructor () {
    this.hash = new sha256('SHA-256', 'TEXT');
  }

  update(x) {
    this.hash.update(x);
    return this;
  }

  digest() {
    return Buffer.from(this.hash.getHash('HEX'), 'hex');
  }
}

export default ReactNativeCrypto;
