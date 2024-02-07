[![CodeQL](https://github.com/Ne0nd0g/winhttp/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ne0nd0g/winhttp/actions/workflows/codeql.yml)
[![GoReportCard](https://goreportcard.com/badge/github.com/Ne0nd0g/winhttp)](https://goreportcard.com/report/github.com/Ne0nd0g/winhttp)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/winhttp.svg)](https://github.com/Ne0nd0g/winhttp/releases/latest)
[![GoDoc](https://godoc.org/github.com/Ne0nd0g/winhttp?status.svg)](https://pkg.go.dev/github.com/Ne0nd0g/winhttp)

# winhttp

`winhttp` is a library used to interact with the Windows [winhttp](https://learn.microsoft.com/en-us/windows/win32/winhttp/about-winhttp) API.

It is designed take in a [http.Request](https://pkg.go.dev/net/http#Request) and return a [http.Response](https://pkg.go.dev/net/http#Response) from the go `http` standard library.
This library returns a custom `Client` that mimics the [http.Client](https://pkg.go.dev/net/http#Client) so that it can be a drop in replacement for the `http.Client`.
This package's custom client also takes an [http.Transport](https://pkg.go.dev/net/http#Transport) structure in the `Transport` field to configure how the winhttp client is used.

## Logging

This package uses the [log/slog](https://pkg.go.dev/log/slog) package for logging. 
To retrieve the log output, create a new logger and call the [slog.SetDefault()](https://pkg.go.dev/log/slog#SetDefault) function.
All loggings calls in this package are only for the `DEBUG` logging level which are not output by default.

## Example

There is an example implementation in the [example](./example) directory.
Run the example code with:

```text
PS C:\> go run .\examples\main.go   
{"time":"2024-02-04T10:00:19.6010954-08:00","level":"INFO","msg":"building the HTTP request"}
{"time":"2024-02-04T10:00:19.60164-08:00","level":"INFO","msg":"building the HTTP client"}
{"time":"2024-02-04T10:00:19.60164-08:00","level":"INFO","msg":"sending the HTTP request","method":"GET","url":"https://httpbin.org/get"}
{"time":"2024-02-04T10:00:19.7671138-08:00","level":"INFO","msg":"recieved HTTP response","response":{"Status":"200 OK","StatusCode":200,"Proto":"HTTP/1.1","ProtoMajor":1,"ProtoMinor":1,"Header":{"Access-Control-Allow-Credentials":["true"],"Access-Control-Allow-Origin":["*"],"Connection":["keep-alive"],"Content-Length":["364"],"Content-Type":["application/json"],"Date":["Sun, 04 Feb 2024 18:00:19 GMT"],"Server":["gunicorn/19.9.0"]},"Body":{"Reader":{}},"ContentLength":364,"TransferEncoding":null,"Close":false,"Uncompressed":false,"Trailer":null,"Request":null,"TLS":null}}
{"time":"2024-02-04T10:00:19.7683439-08:00","level":"INFO","msg":"received HTTP payload data","data length":364}
{"time":"2024-02-04T10:00:19.7683439-08:00","level":"INFO","msg":"program finished running succesfully"}
```

The program's command line flags are:

```text
  -data string
        data to send with the request
  -debug
        enable debug output
  -method string
        the HTTP METHOD for the request (default "GET")
  -trace
        enable SourceKey for debug output
  -url string
        the full URL for the request (default "https://httpbin.org/get")
```