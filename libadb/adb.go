package libadb

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const ADB_HEADER_LENGTH = 24
const SYSTEM_IDENTITY_STRING_HOST = "host::\x00"
const A_CNXN int32 = 0x4e584e43
const A_OPEN int32 = 0x4e45504f
const A_OKAY int32 = 0x59414b4f
const A_CLSE int32 = 0x45534c43
const A_WRTE int32 = 0x45545257
const A_STLS int32 = 0x534c5453

// wireless debug introduced in Android 11, so must use TLS
const A_VERSION int32 = 0x01000001
const MAX_PAYLOAD int32 = 1024 * 1024
const A_STLS_VERSION int32 = 0x01000000

type Message struct {
	command     uint32
	arg0        uint32
	arg1        uint32
	data_length uint32
	data_check  uint32
	magic       uint32
}

type AdbClient struct {
	CertFile string
	KeyFile  string
	PeerName string
}

func get_payload_checksum(data []byte, offset int, length int) int {
	checksum := 0

	// 确保索引不会越界
	endIndex := offset + length
	if endIndex > len(data) {
		endIndex = len(data)
	}

	for i := offset; i < endIndex; i++ {
		checksum += int(data[i])
	}

	return checksum
}

func generate_message(command int32, arg0 int32, arg1 int32, data []byte) []byte {
	var message bytes.Buffer
	binary.Write(&message, binary.LittleEndian, command)
	binary.Write(&message, binary.LittleEndian, arg0)
	binary.Write(&message, binary.LittleEndian, arg1)
	if len(data) != 0 {

		binary.Write(&message, binary.LittleEndian, int32(len(data)))
		checksum := get_payload_checksum(data, 0, len(data))
		binary.Write(&message, binary.LittleEndian, int32(checksum))
	} else {
		binary.Write(&message, binary.LittleEndian, int32(0))
		binary.Write(&message, binary.LittleEndian, int32(0))
	}
	binary.Write(&message, binary.LittleEndian, ^command)
	if len(data) != 0 {
		message.Write(data)
	}
	return message.Bytes()
}

func message_parse(buffer []byte) (Message, error) {
	var header Message
	header.command = binary.LittleEndian.Uint32(buffer[:4])
	header.arg0 = binary.LittleEndian.Uint32(buffer[4:8])
	header.arg1 = binary.LittleEndian.Uint32(buffer[8:12])
	header.data_length = binary.LittleEndian.Uint32(buffer[12:16])
	header.data_check = binary.LittleEndian.Uint32(buffer[16:20])
	header.magic = binary.LittleEndian.Uint32(buffer[20:24])
	return header, nil
}

func VerifyCustomPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

	return nil
}

func (adbClient *AdbClient) Connect(addr string) error {

	// 使用TLS配置创建一个TCP连接
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	// Send CNXN first

	var cnxn_message = generate_message(
		A_CNXN,
		A_VERSION,
		MAX_PAYLOAD,
		[]byte(SYSTEM_IDENTITY_STRING_HOST),
	)
	conn.Write(cnxn_message)

	// Read STLS command
	var message_raw = make([]byte, ADB_HEADER_LENGTH)
	io.ReadFull(conn, message_raw)
	fmt.Printf("message_raw1199:%+v\r\n", message_raw)
	var message, _ = message_parse(message_raw)

	if message.command != uint32(A_STLS) {
		return errors.New("Not STLS command")
	}
	log.Printf("STLS Received message.command:%d\r\n", message.command)

	// Send STLS packet

	var stls_message = generate_message(A_STLS, A_STLS_VERSION, 0, []byte{})
	conn.Write(stls_message)
	log.Printf("STLS Sent\r\n")

	log.Printf("TLS Handshake begin\r\n")
	time.Sleep(time.Second * 1)

	certificates, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)

	tlsConfig := &tls.Config{
		// 客户端证书和私钥
		Certificates: []tls.Certificate{
			certificates,
		},
		ServerName:         addr,
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	}

	tlsconn := tls.Client(conn, tlsConfig)

	message_raw = make([]byte, ADB_HEADER_LENGTH)
	_, err = io.ReadFull(tlsconn, message_raw)
	fmt.Printf("werr:%+v\r\n", err)
	fmt.Printf("message_raw999:%+v\r\n", message_raw)
	message, _ = message_parse(message_raw)
	log.Printf("CNXN Received\r\n")
	var data_raw = make([]byte, message.data_length)

	io.ReadFull(tlsconn, data_raw)
	log.Printf("CNXN data: %+v\r\n", data_raw)

	// Send OPEN

	var shell_cmd = "shell:logcat | grep \x00"
	var open_message = generate_message(A_OPEN, 233, 0, []byte(shell_cmd))
	tlsconn.Write(open_message)
	log.Printf("OPEN Sent\r\n")

	// Read OKAY

	message_raw = make([]byte, ADB_HEADER_LENGTH)
	io.ReadFull(tlsconn, message_raw)

	message, _ = message_parse(message_raw)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
	}
	log.Printf("OKAY Received\r\n")

	// Read WRTE

	message_raw = make([]byte, ADB_HEADER_LENGTH)
	io.ReadFull(tlsconn, message_raw)

	message, _ = message_parse(message_raw)
	if message.command != uint32(A_WRTE) {
		log.Println("Not WRTE command")
	}
	log.Printf("WRTE Received\r\n")

	data_raw = make([]byte, message.data_length)
	io.ReadFull(tlsconn, data_raw)
	log.Printf("WRTE data: %+v\r\n", data_raw)

	// Send OKAY

	var okay_message = generate_message(A_OKAY, 233, 0, []byte{})
	tlsconn.Write(okay_message)
	log.Printf("OKAY Sent\r\n")

	return nil
}
