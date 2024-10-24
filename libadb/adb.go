package libadb

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
)

const ADB_HEADER_LENGTH = 24
const SYSTEM_IDENTITY_STRING_HOST = "host::\x00"
const A_CNXN uint32 = 0x4e584e43
const A_OPEN uint32 = 0x4e45504f
const A_OKAY uint32 = 0x59414b4f
const A_CLSE uint32 = 0x45534c43
const A_WRTE uint32 = 0x45545257
const A_STLS uint32 = 0x534c5453
const A_AUTH uint32 = 0x48545541

/*
#define ID_STAT MKID('S','T','A','T')
#define ID_LIST MKID('L','I','S','T')
#define ID_ULNK MKID('U','L','N','K')
#define ID_SEND MKID('S','E','N','D')
#define ID_RECV MKID('R','E','C','V')
#define ID_DENT MKID('D','E','N','T')
#define ID_DONE MKID('D','O','N','E')
#define ID_DATA MKID('D','A','T','A')
#define ID_OKAY MKID('O','K','A','Y')
#define ID_FAIL MKID('F','A','I','L')
#define ID_QUIT MKID('Q','U','I','T')
*/

// wireless debug introduced in Android 11, so must use TLS
const A_VERSION uint32 = 0x01000001
const MAX_PAYLOAD int32 = 1024 * 1024
const A_STLS_VERSION uint32 = 0x01000000

const ADB_AUTH_TOKEN uint32 = 1
const ADB_AUTH_SIGNATURE uint32 = 2

const ADB_AUTH_RSAPUBLICKEY = 3

func mkid(buf []byte) uint32 {
	return uint32(buf[0]) | (uint32(buf[1]) << 8) | (uint32(buf[2]) << 16) | (uint32(buf[3]) << 24)
}

type Message struct {
	command     uint32
	arg0        uint32
	arg1        uint32
	data_length uint32
	data_check  uint32
	magic       uint32
	payload     []byte
}

type SyncMsg struct {
	id      uint32
	namelen uint32
}

type AdbClient struct {
	CertFile string
	KeyFile  string
	PeerName string
	AdbConn  net.Conn
	LocalId  uint32
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

func generate_message(command uint32, arg0 uint32, arg1 int32, data []byte) []byte {
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

func message_parse(conn net.Conn) (Message, error) {
	var buffer = make([]byte, ADB_HEADER_LENGTH)
	io.ReadFull(conn, buffer)
	var header Message
	header.command = binary.LittleEndian.Uint32(buffer[:4])
	header.arg0 = binary.LittleEndian.Uint32(buffer[4:8])
	header.arg1 = binary.LittleEndian.Uint32(buffer[8:12])
	header.data_length = binary.LittleEndian.Uint32(buffer[12:16])
	header.data_check = binary.LittleEndian.Uint32(buffer[16:20])
	header.magic = binary.LittleEndian.Uint32(buffer[20:24])

	if header.data_length > 0 {
		data_raw := make([]byte, header.data_length)
		io.ReadFull(conn, data_raw)
		header.payload = data_raw
	}
	return header, nil
}

func generate_sync_message(id []byte, len uint32) []byte {
	var message bytes.Buffer
	message.Write(id)
	binary.Write(&message, binary.LittleEndian, len)
	return message.Bytes()
}

func (adbClient *AdbClient) Connect(addr string) error {

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
	var message, _ = message_parse(conn)
	//tls auth
	if message.command == A_STLS {
		// Send STLS packet
		var stls_message = generate_message(A_STLS, A_STLS_VERSION, 0, []byte{})
		conn.Write(stls_message)

		certificates, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)
		if err != nil {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}

		tlsConfig := tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			// 客户端证书和私钥
			Certificates: []tls.Certificate{
				certificates,
			},
			ServerName:         adbClient.PeerName,
			InsecureSkipVerify: true, // 不要跳过证书验证
		}
		//这个设置证书才行
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificates, nil
		}

		// 设置密钥对
		conn = tls.Client(conn, &tlsConfig)

	}

	if message.command == A_AUTH {

		if message.arg0 != ADB_AUTH_TOKEN {
			return errors.New("ddd")
		}

		certificates, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)
		if err != nil {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}

		privateKey, ok := certificates.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}
		c := new(big.Int).SetBytes(message.payload)
		signByte := c.Exp(c, privateKey.D, privateKey.N).Bytes()
		var sign_message = generate_message(A_AUTH, ADB_AUTH_SIGNATURE, 0, signByte)
		conn.Write(sign_message)

		pubKeyByte := adbClient.genPeerInfo(&certificates.PrivateKey.(*rsa.PrivateKey).PublicKey)
		var auth_message = generate_message(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, pubKeyByte)
		conn.Write(auth_message)

	}
	message, _ = message_parse(conn)
	log.Printf("CNXN Received\r\n")
	adbClient.AdbConn = conn

	return nil
}

func (adbClient *AdbClient) Shell(cmd string) error {
	if adbClient.AdbConn == nil {
		return errors.New("not connect")
	}
	adbClient.LocalId++
	// Send OPEN
	var shell_cmd = "shell:" + cmd + "\n \x00"
	var open_message = generate_message(A_OPEN, adbClient.LocalId, 0, []byte(shell_cmd))
	adbClient.AdbConn.Write(open_message)
	log.Printf("OPEN Sent\r\n")

	// Read OKAY
	message, _ := message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
	}
	log.Printf("OKAY Received:%+v\r\n", message.payload)

	// Read WRTE
	message, _ = message_parse(adbClient.AdbConn)
	if message.command != uint32(A_WRTE) {
		log.Println("Not WRTE command")
	}
	log.Printf("WRTE Received:%+v\r\n", string(message.payload))

	// Send OKAY
	var okay_message = generate_message(A_OKAY, adbClient.LocalId, 0, []byte{})
	adbClient.AdbConn.Write(okay_message)
	log.Printf("OKAY Sent\r\n")
	return nil
}

func (adbClient *AdbClient) Ls(path string) error {
	if adbClient.AdbConn == nil {
		return errors.New("not connect")
	}
	adbClient.LocalId++
	// Send OPEN
	var shell_cmd = "sync:"
	var open_message = generate_message(A_OPEN, adbClient.LocalId, 0, []byte(shell_cmd))
	adbClient.AdbConn.Write(open_message)
	log.Printf("OPEN Sent\r\n")

	// Read OKAY
	message, _ := message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
	}
	log.Printf("OKAY message1:%+v\r\n", message)

	//wrte_
	list_message := generate_sync_message([]byte("LIST"), uint32(len(path)))
	wrte_message := generate_message(A_WRTE, adbClient.LocalId, 0, append(list_message, []byte(path)...))
	adbClient.AdbConn.Write(wrte_message)

	//list

	//list_message := generate_sync_message([]byte("LIST"), uint32(len(path)))
	//adbClient.AdbConn.Write(wrte_message)
	//adbClient.AdbConn.Write([]byte(path))
	//fmt.Printf("list_message:%+v\r\n", list_message)
	//adbClient.AdbConn.Write(list_message)
	//adbClient.AdbConn.Write([]byte(path))
	//list
	//pathLen := len(path)
	//wrte_message = generate_sync_message(mkid([]byte("LIST")), uint32(pathLen))
	//adbClient.AdbConn.Write(wrte_message)
	//adbClient.AdbConn.Write([]byte(path))

	var buffer = make([]byte, 9612)
	eee, _ := adbClient.AdbConn.Read(buffer)
	fmt.Printf("bufff:%+v\r\n", buffer[:eee])

	message, _ = message_parse(adbClient.AdbConn)
	log.Printf("WRTE111 message command:%+v\r\n", message.command)

	// Read WRTE
	message, _ = message_parse(adbClient.AdbConn)
	if message.command != uint32(A_WRTE) {
		log.Println("Not WRTE command")
	}
	log.Printf("WRTE222 message command:%+v\r\n", message)

	// Send OKAY
	var okay_message = generate_message(A_OKAY, adbClient.LocalId, 0, []byte{})
	adbClient.AdbConn.Write(okay_message)
	log.Printf("OKAY Sent\r\n")
	return nil
}

func (adbClient *AdbClient) Pull(path string) error {
	if adbClient.AdbConn == nil {
		return errors.New("not connect")
	}
	adbClient.LocalId++
	// Send OPEN
	var shell_cmd = "sync:\x00"
	var open_message = generate_message(A_OPEN, adbClient.LocalId, 0, []byte(shell_cmd))
	adbClient.AdbConn.Write(open_message)
	log.Printf("OPEN Sent\r\n")

	// Read OKAY
	message, _ := message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
	}
	log.Printf("OKAY Received:%+v\r\n", message.payload)

	// Read WRTE
	message, _ = message_parse(adbClient.AdbConn)
	if message.command != uint32(A_WRTE) {
		log.Println("Not WRTE command")
	}
	log.Printf("WRTE Received:%+v\r\n", string(message.payload))

	// Send OKAY
	var okay_message = generate_message(A_OKAY, adbClient.LocalId, 0, []byte{})
	adbClient.AdbConn.Write(okay_message)
	log.Printf("OKAY Sent\r\n")
	return nil
}

func (adbClient *AdbClient) Push(path string) error {
	if adbClient.AdbConn == nil {
		return errors.New("not connect")
	}
	adbClient.LocalId++
	// Send OPEN
	var shell_cmd = "sync:\x00"
	var open_message = generate_message(A_OPEN, adbClient.LocalId, 0, []byte(shell_cmd))
	adbClient.AdbConn.Write(open_message)
	log.Printf("OPEN Sent\r\n")

	// Read OKAY
	message, _ := message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not OKAY command")
	}
	log.Printf("OKAY Received:%+v\r\n", message.payload)

	//list
	wrte_message := generate_message(A_WRTE, adbClient.LocalId, 0, []byte{})
	adbClient.AdbConn.Write(wrte_message)

	// Read WRTE
	message, _ = message_parse(adbClient.AdbConn)
	if message.command != uint32(A_OKAY) {
		log.Println("Not WRTE command")
	}
	log.Printf("WRTE Received:%+v\r\n", string(message.payload))
	//A_CLSE
	// Send OKAY
	var okay_message = generate_message(A_OKAY, adbClient.LocalId, 0, []byte{})
	adbClient.AdbConn.Write(okay_message)
	log.Printf("OKAY Sent\r\n")
	return nil
}
