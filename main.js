const StellarHDWallet = require('stellar-hd-wallet');
const StellarSDK = require('stellar-sdk');
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

// let genKeypair = StellarSDK.Keypair.fromSecret(wallet.getSecret(0));

// console.debug("PK from SK: ", genKeypair.publicKey() );
// console.debug("SK from SK: ", genKeypair.secret() );

// const accFromSeed = StellarHDWallet.fromSeed(wallet.seedHex);

// console.debug("PK from seed: ", accFromSeed.getPublicKey(0));
// console.debug("SK from seed: ", accFromSeed.getSecret(0));

function formatPass(pass) {
    const keySize = 16;
    const key = forge.pkcs5.pbkdf2(pass, eightBytes, 1000, keySize);
    return key;
}

function encrypt(payload, key) {
    const sk = forge.util.createBuffer(payload);

    let cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({iv: sixteenBytes});
    cipher.update(sk);
    cipher.finish();
    let encrypted = cipher.output;
    console.debug("ENCRYPTED: ", encrypted);

    let ciphertextHEX = encrypted.toHex(); //encrypted.getBytes();
    console.debug("ENCRYPTED HEX", ciphertextHEX);

    return ciphertextHEX;
}

function decrypt(cipherHEX, key) {
    let ciphertext = forge.util.hexToBytes(cipherHEX);
    //console.debug("ENCRYPTED bytes", ciphertext);
    
    let decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: sixteenBytes});
    decipher.update(forge.util.createBuffer(ciphertext));
    let result = decipher.finish();
    if(result) {
        console.debug("HEX dectypted: ", decipher.output.data);
        return decipher.output.data;  
    } else {
        console.error("Decryption failed");
    }
}


let encrypted = encrypt(wallet.getPublicKey(0), formatPass(password));
let decrypted = decrypt(encrypted, formatPass(password));

console.log("ENC: ", encrypted);
console.log("DEC: ", decrypted);