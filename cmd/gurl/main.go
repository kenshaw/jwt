// Command gurl signs URLs using Google Service Account credentials for use
// with Google Storage.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kenshaw/jwt/gurl"
	"github.com/mattn/go-isatty"
)

func main() {
	creds := flag.String("creds", "", "google service account credentials")
	method := flag.String("X", "GET", "http method [GET, PUT, DELETE]")
	bucket := flag.String("bucket", "my-test-bucket", "bucket")
	path := flag.String("path", "/test/file.txt", "path")
	exp := flag.Duration("exp", 1*time.Hour, "expiration duration")
	flag.Parse()
	if err := run(*creds, *method, *bucket, *path, *exp); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(creds, method, bucket, path string, exp time.Duration) error {
	signer, err := gurl.FromFile(creds)
	if err != nil {
		return err
	}
	// generate url
	out, err := signer.MakeParams(method, bucket, path, exp, nil)
	if err != nil {
		return err
	}
	// make the output a little nicer
	if isatty.IsTerminal(os.Stdout.Fd()) {
		out += "\n"
	}
	_, err = fmt.Fprintf(os.Stdout, "%s", out)
	return err
}
