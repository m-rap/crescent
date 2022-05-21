class App extends React.Component {

    state = {
        privKey: null,
        pubKey: null,
        symKey: null,
        negoState: 0
    }

    componentDidMount() {
        this.callApi();
    }

    async callApi() {
        let opts = null;
        const rsa = forge.pki.rsa;
        const pki = forge.pki;

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

            let encryptedSymKey = forge.util.decode64(resJson.d4);
            this.state.symKey = keypair.privateKey.decrypt(encryptedSymKey, 'RSA-OAEP', {md: forge.md.sha256.create()});
            this.state.negoState = 1;
        } else if (this.state.negoState == 1) {
            let data = "data rahasia lho";

            let cipher = forge.rc2.createEncryptionCipher(this.state.symKey);
            cipher.start();
            cipher.update(forge.util.createBuffer(data));
            cipher.finish();
            let encryptedData = cipher.output.getBytes();
            let encryptedData64 = forge.util.encode64(encryptedData);

            opts = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({d2: encryptedData64, d5: this.state.negoState})
            }

            const res = await fetch("http://localhost:8080/Api", opts);
            const resJson = await res.json();

            let resEncryptedData = forge.util.decode64(resJson.d2);
            let decCipher = forge.rc2.createDecryptionCipher(this.state.symKey);
            decCipher.start();
            decCipher.update(resEncryptedData);
            decCipher.finish();
            let resData = JSON.parse(decCipher.output.getBytes().toString());
            console.log("res from server: " + resData);
        }
        
    }

    render() {
        let content;
        
        content = (
            <div>
                <p>Hello, Rian</p>
                <button onClick={() => {
                    this.callApi();
                }}>call api</button>
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