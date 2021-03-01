import { pbkdf2 } from 'pbkdf2';
import * as openpgp from "openpgp";
import {pgpKeychain} from "./crypto_helpers.d"

export async function generateKeys(): Promise<pgpKeychain>{
    const { privateKeyArmored, publicKeyArmored, revocationCertificate } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519',
        userIds: [{name: 'Anonymous' }],
    });
    return {
        privateKey: privateKeyArmored,
        publicKey:  publicKeyArmored
    }
}

export async function pgpEncrypt(pubKey: string, message: string): Promise<string>{
    const publicKey = await openpgp.readKey({ armoredKey: pubKey});
    const encrypted = await openpgp.encrypt({
        message: openpgp.Message.fromText(message),
        publicKeys: publicKey,
    });
    
    return encrypted
}

export async function pgpDecrypt(privKey: string, encryptedMessage: string): Promise<string>{
    const privateKey = await openpgp.readKey({ armoredKey: privKey });
    const message = await openpgp.readMessage({
        armoredMessage: encryptedMessage
    });
    const { data: decrypted } = await openpgp.decrypt({
        message,
        privateKeys: privateKey
    });
    return decrypted
    
}


const configPBKDF2 = {
    iterations: 100000,
    hashBytes: 256,
    digest: 'sha512'
};

export function PBKDF2(secret: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const {
            iterations,
            hashBytes,
            digest
        } = configPBKDF2;
        pbkdf2(secret, salt, iterations, hashBytes, digest, (err: any, key: any) => {
            if (err) return reject(err);
            resolve(key.toString('hex'));
        });
    })
}

// (async function () {
//     const {privateKey, publicKey} = await generateKeys();
//     console.log(privateKey, publicKey)
//     const encrypted = await pgpEncrypt(String(publicKey), "hello there")
//     console.log("ENCRYPTED MESSAGE:\n"+encrypted)
//     const decrypted = await pgpDecrypt(privateKey,encrypted)
//     console.log("DECRYPTED MESSAGE:\n"+decrypted)
// })();