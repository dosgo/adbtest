package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/dosgo/spake2-go/spake2"
	"golang.org/x/crypto/hkdf"
)

const (
	clientName = "adb pair client\x00"
	serverName = "adb pair server\x00"
	info       = "adb pairing_auth aes-128-gcm key"
	hkdfKeyLen = 16 // 128 bits

	gcmIVLen = 12
)

type PairingAuthCtx struct {
	spacke2Ctx *spake2.Spake2Ctx
	secretKey  []byte
	password   []byte
	decIV      uint64
	encIV      uint64
}

func CreateAlice(password []byte) (*PairingAuthCtx, error) {
	return createPairingAuthCtx(0, password)
}

func createPairingAuthCtx(myRole int, _password []byte) (*PairingAuthCtx, error) {

	alice, _ := spake2.SPAKE2_CTX_new(myRole, []byte(clientName), []byte(serverName))

	return &PairingAuthCtx{
		spacke2Ctx: alice,
		password:   _password,
		secretKey:  make([]byte, 16),
	}, nil
}

func (p *PairingAuthCtx) GetMsg() ([]byte, error) {
	return p.spacke2Ctx.SPAKE2_generate_msg(p.password)
}

func (p *PairingAuthCtx) ProcessMsg(theirMsg []byte) (bool, error) {
	var err error
	buf, err := p.spacke2Ctx.SPAKE2_process_msg(theirMsg)
	if err != nil {
		return false, err
	}

	var keyInfo = "adb pairing_auth aes-128-gcm key"

	// 创建一个新的HKDF实例，使用SHA-256作为哈希函数
	hkdfExtractor := hkdf.New(sha256.New, buf, nil, []byte(keyInfo))

	p.secretKey = make([]byte, hkdfKeyLen)
	// 生成密钥
	if _, err := hkdfExtractor.Read(p.secretKey); err != nil {
		fmt.Printf("Error generating key: %v\n", err)

	}
	fmt.Printf("p.secretKey[:]:%s\r\n", string(p.secretKey))

	return true, nil
}

func (p *PairingAuthCtx) Encrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.secretKey)
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
	log.Printf("iv:%v\r\n", iv)

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

	iv := make([]byte, gcmIVLen)
	if len(in) < gcmIVLen {
		return nil, fmt.Errorf("ciphertext too short")
	}

	ciphertext := in
	binary.LittleEndian.PutUint64(iv, p.decIV)
	p.decIV++

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func genPeerInfo(name string) []byte {
	publicKey, _ := readRSAPublicKeyFromFile("ddd.pem")

	ADB_RSA_PUB_KEY := byte(0)
	var ANDROID_PUBKEY_ENCODED_SIZE = 524

	// 计算pkeySize
	pkeySize := 4 * int(math.Ceil(float64(ANDROID_PUBKEY_ENCODED_SIZE)/3.0))

	// 创建一个足够大的缓冲区
	buf := new(bytes.Buffer)
	buf.Grow(pkeySize + len(name) + 2)

	// 编码公钥
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)
	if _, err := buf.Write([]byte(encodedPublicKey)); err != nil {
		return nil
	}

	// 获取并写入用户信息
	userInfo := fmt.Sprintf(" %s\u0000", name)
	if _, err := buf.Write([]byte(userInfo)); err != nil {
		return nil
	}
	return append([]byte{ADB_RSA_PUB_KEY}, buf.Bytes()...)

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

	var password = "866503"
	// 使用TLS配置创建一个TCP连接
	conn, err := tls.Dial("tcp", "192.168.78.70:36869", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	conn.Handshake()
	defer conn.Close()
	state := conn.ConnectionState()

	keyMaterial, err := state.ExportKeyingMaterial("adb-label\x00", nil, 64)

	fmt.Printf("keyMaterial:%v err:%v\r\n", keyMaterial, err)
	// 创建Alice（客户端）
	alice, err := CreateAlice(append([]byte(password), keyMaterial...))
	if err != nil {
		log.Fatalf("Failed to create Alice: %v", err)
	}

	// 发送客户端的消息
	clientMsg, err := alice.GetMsg()
	if err != nil {
		log.Fatalf("Failed to get client message: %v", err)
	}
	fmt.Printf("clientMsg:%v\r\n", clientMsg)

	headerBuf := packetHeader(1, 0, uint32(len(clientMsg[:])))
	_, err = conn.Write(headerBuf)
	fmt.Printf("hand:%v\r\n", headerBuf)
	_, err = conn.Write(clientMsg[1:])
	if err != nil {
		log.Fatalf("Failed to write to device: %v", err)
	}

	_, _, headerLen := readPacketHeader(conn)
	fmt.Printf("headerLen:%d\r\n", headerLen)
	buf := make([]byte, 1024*10)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read from device: %v", err)
	}
	serverMsg := buf[:n]

	fmt.Printf("buf:%v\r\n", serverMsg)

	ok, err := alice.ProcessMsg(serverMsg)
	if !ok || err != nil {
		log.Fatalf("Failed to process server message: %v", err)
	}

	// 测试加密和解密
	peerInfo := genPeerInfo("test")
	fmt.Printf("peerInfo:%v\r\n", peerInfo)
	ciphertext, err := alice.Encrypt(peerInfo)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	peerInfoHead := packetHeader(1, 1, uint32(len(ciphertext)))
	conn.Write(peerInfoHead)
	fmt.Printf("peerInfoHead:%v\r\n", peerInfoHead)
	_, err = conn.Write(ciphertext)
	if err != nil {
		log.Fatalf("Failed to write encrypted data: %v", err)
	}

	_, _, peerInfoLen := readPacketHeader(conn)
	fmt.Printf("peerInfoLen:%d\r\n", peerInfoLen)
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

func readPacketHeader(r io.Reader) (byte, byte, uint32) {
	var version byte
	var msgType byte
	var payloadSize uint32
	// 读取版本号
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return version, msgType, payloadSize
	}

	// 读取消息类型
	if err := binary.Read(r, binary.BigEndian, &msgType); err != nil {
		return version, msgType, payloadSize
	}

	// 读取负载大小
	if err := binary.Read(r, binary.BigEndian, &payloadSize); err != nil {
		return version, msgType, payloadSize
	}

	return version, msgType, payloadSize
}

func packetHeader(version byte, msgType byte, payloadSize uint32) []byte {
	var sendBuf bytes.Buffer
	//version := byte(1)
	//msgType := byte(0)                       // 类型
	//payloadSize := int32(len(clientMsg[1:])) // 负载大小

	// 使用binary.Write将字段按大端字节序写入缓冲区
	if err := binary.Write(&sendBuf, binary.BigEndian, version); err != nil {
		fmt.Printf("Error writing version: %v\n", err)
		return nil
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, msgType); err != nil {
		fmt.Printf("Error writing type: %v\n", err)
		return nil
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, payloadSize); err != nil {
		fmt.Printf("Error writing payload size: %v\n", err)
		return nil
	}
	return sendBuf.Bytes()
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

func readRSAPublicKeyFromFile(filename string) ([]byte, error) {
	// 读取文件内容
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// 解析PEM块
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing the certificate")
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 断言公钥类型为*rsa.PublicKey
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the public key is not an RSA public key")
	}

	// 将公钥转换为DER编码的字节切片
	derBytes, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return derBytes, nil
}
