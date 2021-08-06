const StellarHDWallet = require('stellar-hd-wallet');
const StellarSDK = require('stellar-sdk');
const bip39 = require('bip39');
const forge = require("node-forge");

const password = '';
const sixteenBytes = "________________";
const eightBytes = "________";

const mnemonic = StellarHDWallet.generateMnemonic({ entropyBits: 128 }); // 12 words

console.debug("MNEMONIC: ", mnemonic);

const wallet = StellarHDWallet.fromMnemonic(mnemonic, password);
const walletWithoutPass = StellarHDWallet.fromMnemonic(mnemonic);

console.debug("WALLET: ", wallet);

console.debug("WALLET_NO_PASS: ", walletWithoutPass);

//console.debug("PK from raw: ", wallet.getPublicKey(0));
//console.debug("SK from raw: ", wallet.getSecret(0));

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

function validateMnemonic(mnemonic) {
    return StellarHDWallet.validateMnemonic(mnemonic);
}

function pickMnemonicProblem(mnemonic) {
    const mnemonicArr = mnemonic.split(/\s+/).map(w => w.trim());

    let err = "";
    let missing = [];

    if(mnemonicArr.length < 12) err += "Mnemonic is too short. ";

    mnemonicArr.forEach(el => {
        if (!bip39.wordlists['english'].includes(el)) missing.push(el);
    });

    if(missing.length != 0) err += `${missing.join(', ')} cannot be your word(s). `

    return err;
}

console.log("MNEMONIC check ", pickMnemonicProblem('island license town mass cute identify fiction combine indicate cloud food release portion alter disorder'))

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


//let encrypted = encrypt(wallet.getSecret(0), formatPass('vlad'));
//let decrypted = decrypt(encrypted, formatPass("vlad"));

//console.log("ENC: ", encrypted);
//console.log("DEC: ", decrypted);

