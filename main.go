package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"salsa.debian.org/vasudev/gospake2"
	"salsa.debian.org/vasudev/gospake2/ed25519group"
	group "salsa.debian.org/vasudev/gospake2/groups"
)

const (
	clientName = "adb pair client\000"
	serverName = "adb pair server\000"
	info       = "adb pairing_auth aes-128-gcm key"
	hkdfKeyLen = 16 // 128 bits
	gcmIVLen   = 12
)

type PairingAuthCtx struct {
	spacke2Ctx *gospake2.SPAKE2
	secretKey  [hkdfKeyLen]byte
	decIV      uint64
	encIV      uint64
}

func CreateAlice(password string) (*PairingAuthCtx, error) {
	return createPairingAuthCtx(password)
}

func createPairingAuthCtx(_password string) (*PairingAuthCtx, error) {

	var password = gospake2.NewPassword(_password)
	var spake = gospake2.SPAKE2A(password, gospake2.NewIdentityA(clientName), gospake2.NewIdentityB(serverName))
	grp := group.Group(ed25519group.Ed25519{})
	spake.SetGroup(grp)
	return &PairingAuthCtx{
		spacke2Ctx: &spake,
	}, nil
}

func (p *PairingAuthCtx) GetMsg() ([]byte, error) {
	return p.spacke2Ctx.Start(), nil
}

func (p *PairingAuthCtx) ProcessMsg(theirMsg []byte) (bool, error) {
	var err error
	buf, err := p.spacke2Ctx.Finish(theirMsg)
	if err != nil {
		return false, err
	}
	copy(p.secretKey[:], buf[:16])
	return true, nil
}

func (p *PairingAuthCtx) Encrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.secretKey[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, gcmIVLen)
	binary.LittleEndian.PutUint64(iv, p.encIV)
	p.encIV++

	return aesGCM.Seal(nil, iv, in, nil), nil
}

func (p *PairingAuthCtx) Decrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.secretKey[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(in) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := in[:nonceSize], in[nonceSize:]
	binary.LittleEndian.PutUint64(nonce, p.decIV)
	p.decIV++

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func main() {

	var certFile = "ddd.pem"
	var keyFile = "key.pem"

	if !fileExists(certFile) || !fileExists(keyFile) {
		err := generateCert(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to generate certificate: %v", err)
		}
		log.Println("Generated new self-signed certificate")
	} else {
		log.Println("Using existing certificate")
	}

	// 加载客户端证书和私钥
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load client key pair: %v", err)
	}
	// 创建TLS配置，并设置客户端证书
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
	}

	var password = "675276"
	// 使用TLS配置创建一个TCP连接
	conn, err := tls.Dial("tcp", "192.168.78.137:36231", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()

	keyMaterial, err := state.ExportKeyingMaterial("adb-label\u0000", nil, 64)

	fmt.Printf("keyMaterial:%v\r\n", keyMaterial)
	// 创建Alice（客户端）
	alice, err := CreateAlice(password + string(keyMaterial))
	if err != nil {
		log.Fatalf("Failed to create Alice: %v", err)
	}

	// 发送客户端的消息
	clientMsg, err := alice.GetMsg()
	if err != nil {
		log.Fatalf("Failed to get client message: %v", err)
	}
	fmt.Printf("clientMsg:%v\r\n", clientMsg)

	var sendBuf bytes.Buffer
	version := byte(1)
	msgType := byte(0)                       // 类型
	payloadSize := int32(len(clientMsg[1:])) // 负载大小

	// 使用binary.Write将字段按大端字节序写入缓冲区
	if err := binary.Write(&sendBuf, binary.BigEndian, version); err != nil {
		fmt.Printf("Error writing version: %v\n", err)
		return
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, msgType); err != nil {
		fmt.Printf("Error writing type: %v\n", err)
		return
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, payloadSize); err != nil {
		fmt.Printf("Error writing payload size: %v\n", err)
		return
	}
	_, err = conn.Write(sendBuf.Bytes())
	fmt.Printf("hand:%v\r\n", sendBuf.Bytes())
	_, err = conn.Write(clientMsg[1:])
	if err != nil {
		log.Fatalf("Failed to write to device: %v", err)
	}

	// 接收并处理设备的消息
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read from device: %v", err)
	}

	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read from device: %v", err)
	}
	serverMsg := buf[:n]

	fmt.Printf("buf:%v\r\n", serverMsg)

	// 'H' in ASCII

	// 在 original 前面增加 newByte
	newSlice := append([]byte{0x42}, serverMsg...)

	ok, err := alice.ProcessMsg(newSlice)
	if !ok || err != nil {
		log.Fatalf("Failed to process server message: %v", err)
	}

	// 测试加密和解密
	plaintext := []byte("Hello, ADB!")
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	_, err = conn.Write(ciphertext)
	if err != nil {
		log.Fatalf("Failed to write encrypted data: %v", err)
	}

	// 读取并解密设备的响应
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read from device: %v", err)
	}
	encryptedResponse := buf[:n]
	decrypted, err := alice.Decrypt(encryptedResponse)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
	fmt.Printf("Decrypted response from device: %s\n", decrypted)
}

func generateCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 设置证书模板
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1年有效期

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost", // 添加 Common Name
			Organization: []string{"Your Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// 创建证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// 将证书写入文件
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// 将私钥写入文件
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

/*
func  doExchangePeerInfo() {
	// Encrypt PeerInfo
	ByteBuffer buffer = ByteBuffer.allocate(PeerInfo.MAX_PEER_INFO_SIZE).order(ByteOrder.BIG_ENDIAN);
	mPeerInfo.writeTo(buffer);
	byte[] outBuffer = mPairingAuthCtx.encrypt(buffer.array());
	if (outBuffer == null) {
		Log.e(TAG, "Failed to encrypt peer info");
		return false;
	}

	// Write out the packet header
	PairingPacketHeader ourHeader = createHeader(PairingPacketHeader.PEER_INFO, outBuffer.length);
	// Write out the encrypted payload
	writeHeader(ourHeader, outBuffer);

	// Read in the peer's packet header
	PairingPacketHeader theirHeader = readHeader();
	if (theirHeader == null || !checkHeaderType(PairingPacketHeader.PEER_INFO, theirHeader.type)) return false;

	// Read in the encrypted peer certificate
	byte[] theirMsg = new byte[theirHeader.payloadSize];
	mInputStream.readFully(theirMsg);

	// Try to decrypt the certificate
	byte[] decryptedMsg = mPairingAuthCtx.decrypt(theirMsg);
	if (decryptedMsg == null) {
		Log.e(TAG, "Unsupported payload while decrypting peer info.");
		return false;
	}

	// The decrypted message should contain the PeerInfo.
	if (decryptedMsg.length != PeerInfo.MAX_PEER_INFO_SIZE) {
		Log.e(TAG, "Got size=" + decryptedMsg.length + " PeerInfo.size=" + PeerInfo.MAX_PEER_INFO_SIZE);
		return false;
	}

	PeerInfo theirPeerInfo = PeerInfo.readFrom(ByteBuffer.wrap(decryptedMsg));
	Log.d(TAG, theirPeerInfo.toString());
	return true;
}
*/
