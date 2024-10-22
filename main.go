package main

import (
	"adbtest/libadb"
	"bufio"
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

	var adbClient = libadb.AdbClient{"cert.pem", "privateok.key", "uuuu111"}
	err := adbClient.Pair("219444", "192.168.78.34:35391")
	fmt.Printf("err:%+v\r\n", err)
	time.Sleep(time.Second * 1)
	adbClient.Connect("192.168.78.34:33285")

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
