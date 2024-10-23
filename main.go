package main

import (
	"adbtest/libadb"
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {

	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()
	//adbClient.ScanPair(ctx, 980630)
	adbClient.ScanConnect(ctx)
	fmt.Println("按任意键继续...")
	bufio.NewReader(os.Stdin).ReadByte()
}

func privateToPem() {

	// 从文件中读取私钥字节数据
	privateKeyBytes, err := ioutil.ReadFile("private.key")
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	fmt.Printf("privateKey:%+v err:%+v\r\n", privateKey, err)

	rsaPrivKey1, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		//return  errors.New("private key is not of type *rsa.PrivateKey")
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey1)}
	privateKeyFile, err := os.Create("privateok.key")
	if err != nil {
		log.Fatalf("创建私钥文件失败: %v", err)
	}
	defer privateKeyFile.Close()
	pem.Encode(privateKeyFile, privateKeyPEM)
}
