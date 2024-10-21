package main

import (
	"adbtest/libadb"
	"fmt"
	"time"
)

func main() {
	var adbClient = libadb.AdbClient{"cert.pem", "private.key", "uuuu11"}
	err := adbClient.Pair("796676", "192.168.78.222:35591")
	fmt.Printf("err:%+v\r\n", err)
	time.Sleep(time.Second * 1)
	adbClient.Connect("192.168.78.222:35171")
	libadb.StartScanAddr()

	select {}
}
