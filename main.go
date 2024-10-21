package main

import (
	"adbtest/libadb"
	"time"
)

func main() {
	var adbClient = libadb.AdbClient{"ddd.pem", "key.pem", "tes7881"}
	adbClient.Pair("427840", "192.168.78.222:39563")
	time.Sleep(time.Second * 1)
	adbClient.Connect("192.168.78.222:39217")
	libadb.StartScanAddr()

	select {}
}
