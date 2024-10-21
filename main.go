package main

import (
	"adbtest/libadb"
)

func main() {
	var adbClient = libadb.AdbClient{"ddd.pem", "key.pem", "dsafds"}
	//adbClient.Pair("386832", "172.30.16.133:42605")
	adbClient.Connect("172.30.16.133:45339")
	libadb.StartScanAddr()

	select {}
}
