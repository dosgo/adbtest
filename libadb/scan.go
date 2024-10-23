package libadb

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/oleksandr/bonjour"
)

var SERVICE_TYPE_ADB = "adb"
var SERVICE_TYPE_TLS_PAIRING = "adb-tls-pairing"
var SERVICE_TYPE_TLS_CONNECT = "adb-tls-connect"
var resolver *bonjour.Resolver

func StartScanAddr() error {
	var err error
	resolver, err = bonjour.NewResolver(nil)
	if err != nil {
		return err
	}

	results := make(chan *bonjour.ServiceEntry)
	go func(results chan *bonjour.ServiceEntry) {
		for e := range results {
			log.Printf("%s", e.Instance)

		}
	}(results)

	err = resolver.Lookup("adbtest", fmt.Sprintf("_%s._tcp", SERVICE_TYPE_ADB), "", results)
	if err != nil {
		return err
	}
	err = resolver.Lookup("adbtest", fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_PAIRING), "", results)
	if err != nil {
		return err
	}
	err = resolver.Lookup("adbtest", fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_CONNECT), "", results)
	if err != nil {
		return err
	}
	fmt.Printf("dddd")
	return nil
}

func StopScanAddr() {
	resolver.Exit <- true
}

func ScanTest() {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go scanRes(entries)

	entries1 := make(chan *zeroconf.ServiceEntry)
	go scanRes(entries1)

	entries2 := make(chan *zeroconf.ServiceEntry)
	go scanRes(entries2)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	err = resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_ADB), "", entries)
	err = resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_PAIRING), "", entries1)
	err = resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_CONNECT), "", entries2)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}
	fmt.Println("按任意键继续...")
	bufio.NewReader(os.Stdin).ReadByte()
	<-ctx.Done()
	//close(entriesCh)
}

func scanRes(results <-chan *zeroconf.ServiceEntry) {
	for entry := range results {
		log.Println(entry)
	}
	log.Println("No more entries.")
}
