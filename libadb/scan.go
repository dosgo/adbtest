package libadb

import (
	"fmt"
	"log"

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
	return nil
}

func StopScanAddr() {
	resolver.Exit <- true
}
