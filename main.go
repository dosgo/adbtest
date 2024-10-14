package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"

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

	var password = "211285"
	// 使用TLS配置创建一个TCP连接
	conn, err := tls.Dial("tcp", "172.30.17.16:38889", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()

	keyMaterial, err := state.ExportKeyingMaterial("adb-label\u0000", nil, 64)

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
	msgType := byte(0)                   // 类型
	payloadSize := int32(len(clientMsg)) // 负载大小

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
	_, err = conn.Write(clientMsg)
	if err != nil {
		log.Fatalf("Failed to write to device: %v", err)
	}

	// 接收并处理设备的消息
	buf := make([]byte, 1024)
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
