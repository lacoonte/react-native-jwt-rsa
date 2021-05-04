import forge from "node-forge";

const removeB64Padding = base64 => base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function encodeB64(str) {
    const encodedB64 = forge.util.encode64(str);
    return removeB64Padding(encodedB64);
}

export default function sign(privateKey, payload) {
    const key = forge.pki.privateKeyFromPem(privateKey);
    const md = forge.md.sha256.create();
    const header = {
        alg: "RS256",
        typ: "JWT"
    };
    const strHeader = JSON.stringify(header);
    const strPayload = JSON.stringify(payload);
    const header64 = encodeB64(strHeader);
    const payload64 = encodeB64(strPayload);
    const preHash = header64 + '.' + payload64;
    md.update(preHash, 'utf8');
    const signature = key.sign(md);
    const signature64 = encodeB64(signature);
    return header64 + '.' + payload64 + '.' + signature64;
}

