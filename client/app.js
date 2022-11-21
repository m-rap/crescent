
/// <reference path="forge.min.js" />
/// <reference path="react.production.min.js" />
/// <reference path="react-dom.production.min.js" />
/// <reference path="babel.min.js" />
/// <reference path="EncRestClient.js" />

class App extends React.Component {

    state = {
        symKey: null,
    }

    ecrRes = null;

    componentDidMount() {
        this.encRestClient = new EncRestClient();

        //this.callApi();

        //this.testSym();
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
                    this.encRestClient = new EncRestClient();
                }}>reinstantiate encRestClient</button>
                <br/>
                <button onClick={() => {
                    this.encRestClient.post("http://localhost:8080/api/func1", {data: "data rahasia lho"});
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
