import { pbkdf2 } from 'pbkdf2';
const config = {
    iterations: 100000,
    hashBytes: 256,
    digest: 'sha512'
};

export default function PBKDF2(secret: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const {
            iterations,
            hashBytes,
            digest
        } = config;
        pbkdf2(secret, salt, iterations, hashBytes, digest, (err: any, key: any) => {
            if (err) return reject(err);
            resolve(key.toString('hex'));
        });
    })
}
