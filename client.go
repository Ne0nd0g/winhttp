//go:build windows

/*
Copyright (C) 2024 Russel Van Tuyl

winhttp is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

winhttp is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with winhttp.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package winhttp provides an HTTP client using the Windows WinHttp API
package winhttp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Client is an HTTP client used for making HTTP requests using the Windows winhttp API
// This type mimics the Golang http.Client type at https://pkg.go.dev/net/http#Client
// The Transport is optional and the http.DefaultTransport will be used if one is not provided
type Client struct {
	Transport http.RoundTripper
	Timeout   time.Duration
}

// NewHTTPClient returns an HTTP/1.1 client using the Windows WinHTTP API
func NewHTTPClient() (*Client, error) {
	slog.Debug("entering into NewHTTPClient function")
	client := Client{}
	return &client, nil
}

// Do sends an HTTP request and returns an HTTP response using the Windows winhttp API
// The high-level API call flow to send data is WinHttpOpen -> WinHttpConnect -> WinHttpOpenRequest -> WinHttpSendRequest
// The high-level API call flow to receive data is WinHttpReceiveResponse -> WinHttpQueryDataAvailable -> WinHttpReadData
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	slog.Debug("entering into *Client.Do function", "http.Request", fmt.Sprintf("%+v", req))
	resp := http.Response{}

	// Create the Windows HTTP session
	hSession, err := WinHttpOpen(req.UserAgent(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, "", "", WINHTTP_FLAG_NONE)
	if err != nil {
		return nil, err
	}
	defer WinHttpCloseHandle(hSession)

	// See if the Client's transport type exists, if not, set it to the http package's DefaultTransport
	if c.Transport == nil {
		c.Transport = http.DefaultTransport
	}
	// Client only works with *http.Transport type
	if reflect.TypeOf(c.Transport) != reflect.TypeOf(&http.Transport{}) {
		return nil, fmt.Errorf("winhttp expect HTTP Client Transport of type *http.Transport but received: %T", c.Transport)
	}
	transport := c.Transport.(*http.Transport)

	// Apply TLS configurations if any
	if transport.TLSClientConfig != nil {
		// Check to see if TLS minumum or maximum version was set
		vTLS := 0x00000000
		// Check to see if the TLS minimum version is set
		if transport.TLSClientConfig.MinVersion > 0 {
			switch transport.TLSClientConfig.MinVersion {
			case tls.VersionTLS10:
				vTLS = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
			case tls.VersionTLS11:
				vTLS = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
			case tls.VersionTLS12:
				vTLS = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
			case tls.VersionTLS13:
				vTLS = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
			}
		}

		// Check to see if the TLS maximum version is set
		if transport.TLSClientConfig.MaxVersion > 0 {
			switch transport.TLSClientConfig.MaxVersion {
			case tls.VersionTLS10:
				vTLS = vTLS &^ (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
			case tls.VersionTLS11:
				vTLS = vTLS &^ (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
			case tls.VersionTLS12:
				vTLS = vTLS &^ WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
			}
		}

		// If a TLS min/max version was set, configure the winhttp client
		if vTLS > 0 {
			slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_SECURE_PROTOCOLS", "flags", fmt.Sprintf("%08b", uint32(vTLS)))
			buffer := make([]byte, 4)
			binary.LittleEndian.PutUint32(buffer, uint32(vTLS))
			err = WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, buffer)
			if err != nil {
				return nil, err
			}
		}
	}

	// Determine the request server port
	var port int
	if req.URL.Port() == "" {
		port = INTERNET_DEFAULT_PORT
	} else {
		port, err = strconv.Atoi(req.URL.Port())
		if err != nil {
			return nil, fmt.Errorf("http/winhttp/winhttp_windows.go/Do(): there was an error converting '%s' to an integer: %s", req.URL.Port(), err)
		}
	}

	// Create the Windows HTTP connection to the target
	var hConnect windows.Handle
	hConnect, err = WinHttpConnect(hSession, req.Host, uint32(port))
	if err != nil {
		return nil, err
	}
	defer WinHttpCloseHandle(hConnect)

	// Set HTTP Access Types
	accessTypes := []string{WINHTTP_DEFAULT_ACCEPT_TYPES}
	//accessTypes := []string{"text/html", "application/octet-stream", "application/xhtml+xml", "", "application/xml;q=0.9", "image/webp", "*/*;q=0.8"}
	_, OK := req.Header["Accept"]
	if OK {
		accessTypes = req.Header["Accept"]
	}

	// Set HTTP Request Flags
	reqFlags := WINHTTP_FLAG_NONE
	if req.URL.Scheme == "https" {
		reqFlags = reqFlags | WINHTTP_FLAG_SECURE
	}

	// Open the HTTP Request
	var hRequest windows.Handle
	hRequest, err = WinHttpOpenRequest(hConnect, req.Method, req.URL.Path, "", WINHTTP_NO_REFERER, accessTypes, uint32(reqFlags))
	if err != nil {
		return nil, err
	}
	defer WinHttpCloseHandle(hRequest)

	// If a TLS client configuration was provided, use it to configure the winhttp client
	if transport.TLSClientConfig != nil {
		// Check to see if InsecureSkipVerify was set to true
		if transport.TLSClientConfig.InsecureSkipVerify {
			flags := SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
			buffer := make([]byte, 4)
			binary.LittleEndian.PutUint32(buffer, uint32(flags))
			err = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, buffer)
			if err != nil {
				return nil, err
			}
			slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_SECURITY_FLAGS", "flags", fmt.Sprintf("%08b", uint32(flags)))
		}

		// Check to see if TLS next protocols were set
		if len(transport.TLSClientConfig.NextProtos) > 0 {
			var flags int
			for _, proto := range transport.TLSClientConfig.NextProtos {
				switch strings.ToLower(proto) {
				case "h2":
					flags = flags | WINHTTP_PROTOCOL_FLAG_HTTP2
				case "h3":
					flags = flags | WINHTTP_PROTOCOL_FLAG_HTTP3
				}
			}
			buffer := make([]byte, 4)
			binary.LittleEndian.PutUint32(buffer, uint32(flags))
			err = WinHttpSetOption(hRequest, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, buffer)
			if err != nil {
				return nil, err
			}
			slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL", "flags", fmt.Sprintf("%08b", uint32(flags)))
		}
	}

	// See if the Client's timeout value has been set
	// Windows winhttp default connection timeout is 60 seconds, use 0xFFFFFFFF for infinite
	if c.Timeout.Milliseconds() > 0 {
		buffer := make([]byte, 4)
		binary.LittleEndian.PutUint32(buffer, uint32(c.Timeout.Milliseconds()))
		err = WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, buffer)
		if err != nil {
			return nil, err
		}
		slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_CONNECT_TIMEOUT", "time", uint32(c.Timeout.Milliseconds()))
	}

	// See if the response header timeout value has been set
	// Windows winhttp default timeout is 90 seconds
	if transport.ResponseHeaderTimeout.Milliseconds() > 0 {
		buffer := make([]byte, 4)
		binary.LittleEndian.PutUint32(buffer, uint32(transport.ResponseHeaderTimeout.Milliseconds()))
		err = WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, buffer)
		if err != nil {
			return nil, err
		}
		slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT", "time", uint32(transport.ResponseHeaderTimeout.Milliseconds()))
	}

	// See if the response maximum header length value has been set
	// Windows winhttp default maximum header size is 64kb
	if transport.MaxResponseHeaderBytes > 0 {
		buffer := make([]byte, 4)
		binary.LittleEndian.PutUint32(buffer, uint32(transport.MaxResponseHeaderBytes))
		err = WinHttpSetOption(hRequest, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, buffer)
		if err != nil {
			return nil, err
		}
		slog.Debug("set winhttp option", "option", "WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE", "time", uint32(transport.MaxResponseHeaderBytes))
	}

	// See if the request has any headers to be added
	if len(req.Header) > 0 {
		var headers string
		for k, v := range req.Header {
			// Each header except the last must be terminated by a carriage return/line feed (CR/LF)
			headers += fmt.Sprintf("%s: %s", k, strings.Join(v, ", "))
			headers = strings.TrimSuffix(headers, ", ")
			headers += "\r\n"
		}
		headers = strings.TrimSuffix(headers, "\r\n")
		err = WinHttpAddRequestHeaders(hRequest, headers, WINHTTP_ADDREQ_FLAG_ADD)
		if err != nil {
			return nil, err
		}
	}

	// See if there is any data to send
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	optionalDataLength := len(reqBody)

	optionalData := uintptr(WINHTTP_NO_REQUEST_DATA)
	if optionalDataLength > 0 {
		optionalData = uintptr(unsafe.Pointer(&reqBody[0]))
	}

	context := unsafe.Pointer(uintptr(0))

	// Send the HTTP Request
	err = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, optionalData, uint32(optionalDataLength), uint32(optionalDataLength), uintptr(context))
	if err != nil {
		return nil, err
	}

	// Receive the HTTP Response
	err = WinHttpReceiveResponse(hRequest)
	if err != nil {
		return nil, err
	}

	// Get the HTTP Status Code e.g. 200
	var data []byte
	data, err = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE, "", 0)
	if err != nil {
		return nil, err
	}

	// Convert the status code to an integer and store it in the response
	var statusCode string
	statusCode, err = decodeUTF8(data)
	if err != nil {
		return nil, err
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil {
		return nil, fmt.Errorf("winhttp there was an error parsing '%s' to an integer: %s", statusCode, err)
	}
	slog.Debug("retrieved HTTP status code", "status code", resp.StatusCode)

	// Get the HTTP Status e.g. "200 OK"
	data, err = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_TEXT, "", 0)
	if err != nil {
		return nil, err
	}
	var statusText string
	statusText, err = decodeUTF8(data)
	if err != nil {
		return nil, err
	}
	resp.Status = fmt.Sprintf("%s %s", statusCode, statusText)
	slog.Debug("retrieved HTTP status code text", "status code text", resp.Status)

	// Get the HTTP Protocol e.g. "HTTP/1.0"
	data, err = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_VERSION, "", 0)
	if err != nil {
		return nil, err
	}
	resp.Proto, err = decodeUTF8(data)
	if err != nil {
		return nil, err
	}
	slog.Debug("retrieved HTTP version", "version", resp.Proto)

	// Parse the HTTP Protocol Major e.g. 1 in HTTP/1.1
	index := strings.Index(resp.Proto, ".")
	resp.ProtoMajor, err = strconv.Atoi(resp.Proto[index-1 : index])
	if err != nil {
		return nil, fmt.Errorf("there was an error converting '%s' to an integer: %s", resp.Proto[index-1:index], err)
	}

	// Parse the HTTP Protocol Minor e.g. 0 in HTTP/1.0
	resp.ProtoMinor, err = strconv.Atoi(resp.Proto[index+1 : index+2])
	if err != nil {
		return nil, fmt.Errorf("there was an error converting '%s' to an integer: %s", resp.Proto[index+1:index+2], err)
	}

	// Get the HTTP Headers
	data, err = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, "", 0)
	if err != nil {
		return nil, err
	}
	var headers string
	headers, err = decodeUTF8(data)
	if err != nil {
		return nil, err
	}
	slog.Debug("called WinHTTPQueryHeaders", "headers", headers)

	// Parse the headers
	resp.Header = http.Header{}
	for _, header := range strings.SplitAfter(headers, "\r\n") {
		i := strings.Index(header, ":")
		// Ignore headers that do not contain a colon (e.g., HTTP/1.1 200 OK)
		if i != -1 {
			// The 2 is to account for the space after the colon
			resp.Header.Add(header[:i], strings.Trim(header[i+2:], "\r\n"))
		}
	}

	// Loop over available data until completed
	var body []byte
	var i int
	for {
		// Do not use the return value of WinHttpQueryDataAvailable to determine whether the end of a response has been reached,
		// because not all servers terminate responses properly, and an improperly terminated response causes
		// WinHttpQueryDataAvailable to anticipate more data.

		// Get the size of the HTTP Response
		var n uint32
		n, err = WinHttpQueryDataAvailable(hRequest)
		if err != nil {
			return nil, err
		}
		slog.Debug("called WinHttpQueryDataAvailable", "data size", n, "loop count", i)

		// Read the HTTP Response data
		var respData []byte
		respData, err = WinHttpReadData(hRequest, n)
		if err != nil {
			return nil, err
		}
		slog.Debug("called WinHttpReadData", "data length", len(respData), "data", string(respData), "loop count", i)

		// When there is no more data, exit the loop
		if len(respData) <= 0 {
			break
		}

		// Add the data chunk to the response body
		body = append(body, respData...)
		i++
	}

	// Set the Content-Length
	cl, ok := resp.Header["Content-Length"]
	if ok {
		resp.ContentLength, err = strconv.ParseInt(strings.Join(cl, ""), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("there was an error parsing '%s' to a string: %s", strings.Join(cl, ""), err)
		}
	} else {
		resp.ContentLength = int64(len(body))
	}

	// Set the response body
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return &resp, nil
}

// Get issues an HTTP GET request to the specified URL and returns an HTTP response
func (c *Client) Get(url string) (*http.Response, error) {
	slog.Debug("entering into *Client.Get function", "url", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head issues an HTTP HEAD request to the specified URL and returns an HTTP response
func (c *Client) Head(url string) (resp *http.Response, err error) {
	slog.Debug("entering into *Client.Head function", "url", url)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues an HTTP POST request to specified URL and returns an HTTP response
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	slog.Debug("entering into *Client.Post function", "url", url, "contentType", contentType, "body", fmt.Sprintf("%T: %+v", body, body))
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	// Setup the content-type
	req.Header.Set("Content-Type", contentType)

	return c.Do(req)
}
