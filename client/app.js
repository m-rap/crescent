
/// <reference path="forge.min.js" />
/// <reference path="https://unpkg.com/node-forge@1.0.0/dist/forge.min.js" />
/// <reference path="react.production.min.js" />
/// <reference path="react-dom.production.min.js" />
/// <reference path="babel.min.js" />

class App extends React.Component {

    state = {
        privKey: null,
        pubKey: null,
        symKey: null,
        negoState: 0
    }

    componentDidMount() {
        //this.callApi();

        //this.testSym();
    }

    async callApi() {
        let opts = null;
        const rsa = forge.pki.rsa;
        const pki = forge.pki;

        console.log("nego state: " + this.state.negoState);

        if (this.state.negoState == 0) {
            const keypair = rsa.generateKeyPair({bits: 2048});
            let pubKeyPem = pki.publicKeyToPem(keypair.publicKey);
            this.state.privKey = keypair.privateKey;
            this.state.pubKey = keypair.publicKey;
            
            opts = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({d1: pubKeyPem, d5: this.state.negoState})
            }

            const res = await fetch("http://localhost:8080/api", opts);
            const resJson = await res.json();

            console.log("got response " + JSON.stringify(resJson));

            let encryptedSymKey = forge.util.decode64(resJson.d4);
            this.state.symKey = keypair.privateKey.decrypt(encryptedSymKey, 'RSA-OAEP', {md: forge.md.sha256.create()});

            console.log("decrypted symkey: " + this.state.symKey + " len " + this.state.symKey.length);

            this.state.negoState = 1;
        } else if (this.state.negoState == 1) {
            let data = {data: "data rahasia lho"};

            console.log("encrypting data before send to server");

            let iv = forge.random.getBytesSync(16);

            let symKeyBuff = forge.util.createBuffer(this.state.symKey);
            let ivBuff = forge.util.createBuffer(iv);
            console.log("create encryption cipher key "+ symKeyBuff.toHex() +" iv " + ivBuff.toHex());
            let cipher = forge.cipher.createCipher('AES-CBC', this.state.symKey);

            console.log("start cipher");
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(JSON.stringify(data)));
            cipher.finish();
            console.log("cipher finished");

            let encryptedData = cipher.output.bytes();
            let encryptedData64 = forge.util.encode64(encryptedData);
            let iv64 = forge.util.encode64(iv);
            let d2 = iv64+"\\n"+encryptedData64;
            console.log("iv " + iv64 + " d2 " + d2);

            opts = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({d2: d2, d5: this.state.negoState})
            }

            console.log("sending to server");

            const res = await fetch("http://localhost:8080/api", opts);
            const resJson = await res.json();

            console.log("got response from server " + JSON.stringify(resJson));

            console.log("decoding base64");
            let tmp = forge.util.decode64(resJson.d2);
            let resEncryptedData = forge.util.createBuffer(tmp);
            console.log("resEncryptedData " + resEncryptedData.toHex() + " len " + resEncryptedData.length());

            console.log("creating decipher, key "+ symKeyBuff.toHex() + " iv " + ivBuff.toHex());
            //console.log("creating decipher, mode unpad true, key "+ symKeyBuff.toHex() + " iv " + ivBuff.toHex());
            let decipher = forge.cipher.createDecipher('AES-CBC', this.state.symKey);
            //decipher.mode.unpad = true;
            console.log("start decipher");
            decipher.start({iv: iv});
            decipher.update(resEncryptedData);
            let resDecryptedData = decipher.output.getBytes();
            let result = decipher.finish();
            console.log("decipher finished aaa "+result);
            console.log("resDecryptedData "+resDecryptedData);
            let resData = JSON.parse(resDecryptedData);
            console.log("res from server: " + resData);
        }
        
    }

    genSymKey() {
        this.state.symKey = forge.random.getBytesSync(16);
    }

    testSym() {
        let data = {data: "data rahasia lho"};

        console.log("encrypting data before send to server");

        let iv = forge.random.getBytesSync(16);
        if (this.state.symKey == null) {
            this.state.symKey = forge.random.getBytesSync(16);
        }

        console.log("create encryption cipher key "+this.state.symKey+" iv " + iv);
        let cipher = forge.cipher.createCipher('AES-CBC', this.state.symKey);

        console.log("start cipher");
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(JSON.stringify(data)));
        cipher.finish();
        console.log("cipher finished");

        let encryptedData = cipher.output.bytes();

        console.log("encryptedData " + encryptedData + " len " + encryptedData.length);

        let decipher = forge.cipher.createDecipher('AES-CBC', this.state.symKey);
        console.log("start decipher");
        decipher.start({iv: iv});
        decipher.update(forge.util.createBuffer(encryptedData));
        let result = decipher.finish();
        let resDecryptedData = decipher.output.getBytes();
        console.log("decrypted: " + resDecryptedData);
    }

    render() {
        let content;
        
        content = (
            <div>
                <p>Hello, Rian</p>
                <button onClick={() => {
                    this.callApi();
                }}>call api</button>
                <br/>
                <button onClick={() => {
                    this.testSym();
                }}>test</button>
                <br/>
                <button onClick={() => {
                    this.genSymKey();
                }}>gen symKey</button>
            </div>
        );

        return (
            <div>
                <p>hello world from app</p>
                { content }
            </div>
        );
    }
}

const domContainer = document.getElementById('app');
const root = ReactDOM.createRoot(domContainer);
root.render(<App />);
