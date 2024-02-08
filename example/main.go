//go:build windows

package main

import (
	// Standard
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	// Internal
	"github.com/Ne0nd0g/winhttp"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug output")
	trace := flag.Bool("trace", false, "enable SourceKey for debug output")
	method := flag.String("method", "GET", "the HTTP METHOD for the request")
	url := flag.String("url", "https://httpbin.org/get", "the full URL for the request")
	httpData := flag.String("data", "", "data to send with the request")
	flag.Parse()

	// Setup logger
	opts := slog.HandlerOptions{}
	if *debug {
		opts.Level = slog.LevelDebug
	}
	if *trace {
		opts.AddSource = true
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &opts))
	slog.SetDefault(logger)

	// Build the HTTP
	slog.Info("building the HTTP request")
	req, err := http.NewRequest(strings.ToUpper(*method), *url, bytes.NewReader([]byte(*httpData)))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0")

	// Get the HTTP client
	slog.Info("building the HTTP client")
	client, err := winhttp.NewHTTPClient()
	if err != nil {
		log.Fatal(err)
	}

	// Build TLS Client Config and add it to the client
	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	transport := http.Transport{
		TLSClientConfig:        &tlsConfig,
		TLSHandshakeTimeout:    240 * time.Second,
		MaxResponseHeaderBytes: 0,
	}
	client.Transport = &transport

	// Send the request
	slog.Info("sending the HTTP request", "method", *method, "url", *url)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("received HTTP response", "response", resp)

	n := int64(0)
	body := new(strings.Builder)
	if resp.Body != nil {
		n, err = io.Copy(body, resp.Body)
		if err != nil {
			log.Fatal(err)
		}
	}

	if n > 0 {
		slog.Info("received HTTP payload data", "data length", n)
		if *debug {
			fmt.Printf("[+] HTTP Data:\n%s\n", body)
		}
	}
	slog.Info("program finished running successfully")
}
