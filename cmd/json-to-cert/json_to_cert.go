package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/grantae/certinfo"
)

var format = flag.String("format", "text", "text|json|pem")

func main() {
	flag.Parse()

	var printFunc func(cert *ctx509.Certificate)
	switch *format {
	case "text":
		printFunc = printText
	case "json":
		printFunc = printJson
	case "pem":
		printFunc = printPem
	default:
		log.Fatalf("invalid -format flag")
	}

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalf("usage: %s <cert.json>", os.Args[0])
	}

	f, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}

	dec := json.NewDecoder(f)
	var rawEntry ct.LeafEntry
	err = dec.Decode(&rawEntry)
	if err != nil {
		log.Fatal(err)
	}

	logEntry, err := ct.LogEntryFromLeaf(0, &rawEntry)
	if err != nil {
		log.Fatal(err)
	}

	if logEntry.X509Cert != nil {
		printFunc(logEntry.X509Cert)
	} else if logEntry.Precert != nil {
		printFunc(logEntry.Precert.TBSCertificate)
	}

}

func printText(ctcert *ctx509.Certificate) {
	cert, err := x509.ParseCertificate(ctcert.Raw)
	if err != nil {
		log.Fatal(err)
	}
	txt, err := certinfo.CertificateText(cert)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(txt)
}

func printJson(cert *ctx509.Certificate) {
	j, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(j))
}

func printPem(cert *ctx509.Certificate) {
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fmt.Println(string(pemCert))
}
