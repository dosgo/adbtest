package main

import (
	"adbtest/libadb"
)

func main() {
	var adbClient = libadb.AdbClient{"ddd.pem", "key.pem", "test997710"}
	adbClient.Pair("369010", "192.168.78.116:40537")
	adbClient.Connect("192.168.78.116:40695")
	libadb.StartScanAddr()

	select {}
}
