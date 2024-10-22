package main

import (
	"adbtest/libadb"
	"bufio"
	"fmt"
	"os"
	"time"
)

func main() {

	var adbClient = libadb.AdbClient{"cert.pem", "private.key", "uuuu11"}
	//err := adbClient.Pair("425838", "192.168.78.34:41091")
	//fmt.Printf("err:%+v\r\n", err)
	time.Sleep(time.Second * 1)
	adbClient.Connect("192.168.78.34:33285")

	fmt.Println("按任意键继续...")
	bufio.NewReader(os.Stdin).ReadByte()
}
