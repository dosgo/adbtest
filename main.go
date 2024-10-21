package main

import (
	"adbtest/libadb"
	"bufio"
	"fmt"
	"os"
)

func main() {
	/*
		var adbClient = libadb.AdbClient{"cert.pem", "private.key", "uuuu11"}
		err := adbClient.Pair("796676", "192.168.78.222:35591")
		fmt.Printf("err:%+v\r\n", err)
		time.Sleep(time.Second * 1)
		adbClient.Connect("192.168.78.222:35171")
	*/
	libadb.DDD()

	fmt.Println("按任意键继续...")
	bufio.NewReader(os.Stdin).ReadByte()
}
