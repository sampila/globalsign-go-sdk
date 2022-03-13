/*
 * This example showcases how to digitally sign a PDF file using GlobalSign
 * Digital Signing Service and integrate it with UniPDF.
 * To get UniPDF go to: https://github.com/unidoc/unipdf.
 *
 * $ ./main <INPUT_PDF_PATH> <OUTPUT_PDF_PATH>
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/unidoc/unipdf/v3/common"
	"github.com/unidoc/unipdf/v3/common/license"
)

func init() {
	// Make sure to load your metered License API key prior to using the library.
	// If you need a key, you can sign up and create a free one at https://cloud.unidoc.io
	err := license.SetMeteredKey(os.Getenv(`UNIDOC_LICENSE_API_KEY`))
	if err != nil {
		panic(err)
	}

	// Set logger.
	common.SetLogger(common.NewConsoleLogger(common.LogLevelDebug))
}

var (
	inputFile  string
	outputFile string
	email      string
	fullname   string
	reason     string

	certPath string
	keyPath  string

	apiKey     = ""
	apiSecret  = ""
	apiBaseURL = "https://emea.api.dss.globalsign.com:8443"
)

func main() {
	flag.StringVar(&inputFile, "input-file", "", "file to be signed (required)")
	flag.StringVar(&outputFile, "output-file", "", "output result (required)")
	flag.StringVar(&email, "email", "", "email for signer identity (required)")
	flag.StringVar(&apiKey, "api-key", "", "API key (required)")
	flag.StringVar(&apiSecret, "api-secret", "", "API secret (required)")
	flag.StringVar(&certPath, "cert-file", "tls.cer", "certificate file for API (required)")
	flag.StringVar(&keyPath, "key-file", "key.pem", "key file for API (required)")
	flag.StringVar(&fullname, "name", "your n@me", "signer name")
	flag.StringVar(&reason, "reason", "enter your re@son", "signing reason")

	flag.Parse()

	if inputFile == "" || outputFile == "" || email == "" || apiKey == "" || apiSecret == "" || certPath == "" || keyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	option := &SignOption{
		SignedBy: "UniDoc",
		Fullname: "Alip Sulistio",
		Reason:   "GlobalSign DSS Testing",
		Annotate: true,
	}

	sigGen := NewGlobalSignDssSigner(map[string]interface{}{
		"provider.globalsign.api_url":     apiBaseURL,
		"provider.globalsign.api_key":     apiKey,
		"provider.globalsign.api_secret":  apiSecret,
		"provider.globalsign.certificate": certPath,
		"provider.globalsign.private_key": keyPath,
	})

	if err := SignFile(context.Background(), inputFile, outputFile, option, sigGen); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("File signed successfully")
}
