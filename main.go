package crescent

import (
	"crypto/aes"
	"crypto/cipher"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"

	//"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type EncNegoClientParams struct {
	D1 string `json:"d1"`
	D2 string `json:"d2"`
	D3 bool   `json:"d3"`
	D4 string `json:"d4"`
	D5 int    `json:"d5"`
}

type ClientInfo struct {
	Uuid   string
	PubKey *rsa.PublicKey
	SymKey []byte
}

var clientInfoMap map[string]ClientInfo
var clientInfo ClientInfo
var clientData map[string]interface{}
var aesCipher cipher.Block
var iv []byte
var params EncNegoClientParams

func Negotiate(c *gin.Context) {
	state := 0

	//raw, _ := c.GetRawData()
	//fmt.Printf("request %v\n", string(raw))

	c.ShouldBindJSON(&params)

	id, err := c.Cookie("uuid")

	if err != nil {
		fmt.Printf("id not exists: %s:%T,%s:%T\n", id, id, err, err)
	} else {
	}

	fmt.Printf("params d5 %v\n", params.D5)
	if params.D5 >= 0 {
		state = params.D5
		fmt.Printf("request nego state %v %d\n", params.D5, state)
	}

	fmt.Printf("nego state %d\n", state)

	switch state {
	case 0:
		if strings.Trim(params.D1, " ") == "" {
			c.JSON(200, gin.H{
				"msg": "invalid params",
			})
			return
		}

		pubKeyPemBlock, _ := pem.Decode([]byte(params.D1))
		if pubKeyPemBlock == nil {
			fmt.Printf("can't find pem block.\n")
			c.Abort()
			return
		}
		fmt.Printf("pem block: %v\n", pubKeyPemBlock)
		pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyPemBlock.Bytes)
		pubKey, _ := pubKeyInterface.(*rsa.PublicKey)
		if err != nil {
			fmt.Printf("failed parse pem block: %s\n", err.Error())
			c.Abort()
			return
		}

		id = uuid.NewString()
		symKey := make([]byte, aes.BlockSize)
		rand.Seed(time.Now().Unix())
		rand.Read(symKey)
		encryptedSymKey, _ := rsa.EncryptOAEP(sha256.New(), cRand.Reader, pubKey, symKey, nil)
		encryptedSymKeyB64 := base64.StdEncoding.EncodeToString(encryptedSymKey)

		fmt.Println("set cookie")
		c.SetCookie("uuid", id, 10*365*24*60*60, "/", "localhost", false, true)
		fmt.Println("write response in json")
		c.JSON(200, gin.H{
			"d4": encryptedSymKeyB64,
		})
		fmt.Println("abort because still state 0")
		c.Abort()

		aClientInfo := ClientInfo{
			Uuid:   id,
			SymKey: symKey,
			PubKey: pubKey,
		}
		fmt.Printf("add client info %s to map\n", id)
		clientInfoMap[id] = aClientInfo

	case 1:
		var ok bool
		clientInfo, ok = clientInfoMap[id]

		if !ok {
			c.JSON(200, gin.H{
				"d3":  0,
				"msg": "not negotiated yet",
			})
			return
		}

		fmt.Printf("state 1, d2: %v\n", params.D2)
		fmt.Printf("client info %s, symkey %x\n", clientInfo.Uuid, clientInfo.SymKey)
		aesCipher, err = aes.NewCipher(clientInfo.SymKey)
		if err != nil {
			fmt.Printf("failed creating cipher %s\n", err.Error())
			c.Abort()
			return
		}
		d2Arr := strings.Split(params.D2, "\\n")
		if len(d2Arr) < 2 {
			c.JSON(200, gin.H{
				"d3":  0,
				"msg": "invalid data",
			})
			c.Abort()
			return
		}
		iv, err = base64.StdEncoding.DecodeString(d2Arr[0])
		if err != nil {
			fmt.Printf("error decoding iv %s\n", err.Error())
			c.Abort()
			return
		}
		fmt.Printf("iv %x\n", iv)
		decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
		encryptedData, _ := base64.StdEncoding.DecodeString(d2Arr[1])
		dataLen := len(encryptedData)
		data := make([]byte, dataLen)
		decrypter.CryptBlocks(data, encryptedData)
		lastByte := data[dataLen-1]
		if !unicode.IsGraphic(rune(lastByte)) {
			data = data[:dataLen-int(lastByte)]
		}
		dataStr := string(data)
		fmt.Printf("clientData decrypted %v byte %v\n", dataStr, data)
		if err = json.Unmarshal(data, &clientData); err != nil {
			fmt.Printf("unmarshal failed %s\n", err.Error())
			c.Abort()
			return
		}
		fmt.Printf("clientData unmarshalled %v\n", clientData)
		//c.Set("data", dataJson)
		//c.Set("cipher", aesCipher)
		//c.Set("iv", iv)
		//c.Next()

		//Api(c)
	}
}

func SendEncRestResponse(responseStr string, c *gin.Context) {
	responseStrLen := len(responseStr)
	remain := aes.BlockSize - responseStrLen%aes.BlockSize
	resDataLen := responseStrLen + remain

	fmt.Printf("responseStrLen %d remain %d resDataLen %d\n", responseStrLen, remain, resDataLen)

	resData := make([]byte, resDataLen)
	resDataEncrypted := make([]byte, resDataLen)

	copy(resData, responseStr)
	fmt.Printf("pad/remain: %d\n", remain)
	for i := responseStrLen; i < resDataLen; i++ {
		resData[i] = byte(remain)
	}

	fmt.Printf("create encrypter. symkey %x\niv %x\n", clientInfo.SymKey, iv)
	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	encrypter.CryptBlocks(resDataEncrypted, resData)
	resDataEncrypted64 := base64.StdEncoding.EncodeToString(resDataEncrypted)

	fmt.Printf("resDataEncrypted %x len %d\n", resDataEncrypted, resDataLen)

	//fmt.Printf("create decrypter. symkey %x\niv %x\n", clientInfo.SymKey, iv)
	//decrypted := make([]byte, resDataLen)
	//decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	//decrypter.CryptBlocks(decrypted, resDataEncrypted)

	//fmt.Printf("decrypted: %s\n%x\n", decrypted, decrypted)

	c.JSON(200, gin.H{
		"d2": resDataEncrypted64,
	})
}

func testSym() {
	symKey := make([]byte, 32)
	rand.Seed(time.Now().Unix())
	rand.Read(symKey)

	iv := make([]byte, aes.BlockSize)
	rand.Seed(time.Now().Unix() + 123)
	rand.Read(iv)

	responseStr := "{\"data\": \"data rahasia balasan lho\"}"
	responseStrLen := len(responseStr)
	remain := aes.BlockSize - responseStrLen%aes.BlockSize
	resDataLen := responseStrLen + remain
	resData := make([]byte, resDataLen)
	copy(resData, responseStr)
	fmt.Printf("pad/remain: %d\n", remain)
	for i := responseStrLen; i < resDataLen; i++ {
		resData[i] = byte(remain)
	}

	resDataEncrypted := make([]byte, resDataLen)
	aesCipher, _ := aes.NewCipher(symKey)

	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	encrypter.CryptBlocks(resDataEncrypted, resData)
	fmt.Printf("encrypted str size %d, data size %d\n", responseStrLen, resDataLen)

	resDataDecrypted := make([]byte, resDataLen)
	decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypter.CryptBlocks(resDataDecrypted, resDataEncrypted)
	lastByte := resDataDecrypted[resDataLen-1]
	if !unicode.IsGraphic(rune(lastByte)) {
		resDataDecrypted = resDataDecrypted[:resDataLen-int(lastByte)]
	}
	fmt.Printf("decrypted: %s (%d)\n", string(resDataDecrypted), len(resDataDecrypted))
}

func Init() {
	clientInfoMap = make(map[string]ClientInfo)
}
