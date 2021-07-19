const StellarHDWallet = require('stellar-hd-wallet');
const forge = require("node-forge");

const password = 'password';
const sixteenBytes = "________________";
const eightBytes = "________";

const mnemonic = StellarHDWallet.generateMnemonic({ entropyBits: 128 }); // 12 words

console.debug("MNEMONIC: ", mnemonic);

const wallet = StellarHDWallet.fromMnemonic(mnemonic, password);

console.debug("WALLET: ", wallet);

console.debug("PK from raw: ", wallet.getPublicKey(0));
console.debug("SK from raw: ", wallet.getSecret(0));

// const accFromSeed = StellarHDWallet.fromSeed(wallet.seedHex);

// console.debug("PK from seed: ", accFromSeed.getPublicKey(0));
// console.debug("SK from seed: ", accFromSeed.getSecret(0));

function formatPass(pass) {
    const keySize = 16;
    const key = forge.pkcs5.pbkdf2(pass, eightBytes, 1000, keySize);
    return key;
}

const sk = forge.util.createBuffer(wallet.getPublicKey(0));

var cipher = forge.cipher.createCipher('AES-CBC', formatPass(password));
cipher.start({iv: sixteenBytes});
cipher.update(sk);
cipher.finish();
var encrypted = cipher.output;
console.log("ENCRYPTED: ", encrypted);

let ciphertext = encrypted.getBytes();

var decipher = forge.cipher.createDecipher('AES-CBC', formatPass(password));
decipher.start({iv: sixteenBytes});
decipher.update(forge.util.createBuffer(ciphertext));
var result = decipher.finish();

if(result) {
    console.log("HEX dectypted: ", decipher.output.data);   
}