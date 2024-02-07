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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// WinHTTP!WinHttpOpen dwAccessType
	// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen
	WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   = 0
	WINHTTP_ACCESS_TYPE_NO_PROXY        = 1
	WINHTTP_ACCESS_TYPE_NAMED_PROXY     = 3
	WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

	// WinHTTP pszProxyW
	WINHTTP_NO_PROXY_NAME = 0

	// WinHTTP pszProxyBypassW
	WINHTTP_NO_PROXY_BYPASS = 0

	// WinHTTP dwFlags
	WINHTTP_FLAG_NONE                 = 0x00000000
	WINHTTP_FLAG_ASYNC                = 0x10000000
	WINHTTP_FLAG_SECURE_DEFAULTS      = 0x30000000
	WINHTTP_FLAG_SECURE               = 0x00800000
	WINHTTP_FLAG_ESCAPE_PERCENT       = 0x00000004
	WINHTTP_FLAG_NULL_CODEPAGE        = 0x00000008
	WINHTTP_FLAG_ESCAPE_DISABLE       = 0x00000040
	WINHTTP_FLAG_ESCAPE_DISABLE_QUERY = 0x00000080
	WINHTTP_FLAG_BYPASS_PROXY_CACHE   = 0x00000100
	WINHTTP_FLAG_REFRESH              = WINHTTP_FLAG_BYPASS_PROXY_CACHE
	WINHTTP_FLAG_AUTOMATIC_CHUNKING   = 0x00000200

	// INTERNET_PORT https://learn.microsoft.com/en-us/windows/win32/winhttp/internet-port
	INTERNET_DEFAULT_PORT       = 0
	INTERNET_DEFAULT_HTTP_PORT  = 80
	INTERNET_DEFAULT_HTTPS_PORT = 443

	WINHTTP_NO_ADDITIONAL_HEADERS = ""

	// HTTP Query Flags
	WINHTTP_QUERY_MIME_VERSION              = 0
	WINHTTP_QUERY_CONTENT_TYPE              = 1
	WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING = 2
	WINHTTP_QUERY_CONTENT_ID                = 3
	WINHTTP_QUERY_CONTENT_DESCRIPTION       = 4
	WINHTTP_QUERY_CONTENT_LENGTH            = 5
	WINHTTP_QUERY_CONTENT_LANGUAGE          = 6
	WINHTTP_QUERY_ALLOW                     = 7
	WINHTTP_QUERY_PUBLIC                    = 8
	WINHTTP_QUERY_DATE                      = 9
	WINHTTP_QUERY_EXPIRES                   = 10
	WINHTTP_QUERY_LAST_MODIFIED             = 11
	WINHTTP_QUERY_MESSAGE_ID                = 12
	WINHTTP_QUERY_URI                       = 13
	WINHTTP_QUERY_DERIVED_FROM              = 14
	WINHTTP_QUERY_COST                      = 15
	WINHTTP_QUERY_LINK                      = 16
	WINHTTP_QUERY_PRAGMA                    = 17
	WINHTTP_QUERY_VERSION                   = 18
	WINHTTP_QUERY_STATUS_CODE               = 19
	WINHTTP_QUERY_STATUS_TEXT               = 20
	WINHTTP_QUERY_RAW_HEADERS               = 21
	WINHTTP_QUERY_RAW_HEADERS_CRLF          = 22
	WINHTTP_QUERY_CONNECTION                = 23
	WINHTTP_QUERY_ACCEPT                    = 24
	WINHTTP_QUERY_ACCEPT_CHARSET            = 25
	WINHTTP_QUERY_ACCEPT_ENCODING           = 26
	WINHTTP_QUERY_ACCEPT_LANGUAGE           = 27
	WINHTTP_QUERY_AUTHORIZATION             = 28
	WINHTTP_QUERY_CONTENT_ENCODING          = 29
	WINHTTP_QUERY_FORWARDED                 = 30
	WINHTTP_QUERY_FROM                      = 31
	WINHTTP_QUERY_IF_MODIFIED_SINCE         = 32
	WINHTTP_QUERY_LOCATION                  = 33
	WINHTTP_QUERY_ORIG_URI                  = 34
	WINHTTP_QUERY_REFERER                   = 35
	WINHTTP_QUERY_RETRY_AFTER               = 36
	WINHTTP_QUERY_SERVER                    = 37
	WINHTTP_QUERY_TITLE                     = 38
	WINHTTP_QUERY_USER_AGENT                = 39
	WINHTTP_QUERY_WWW_AUTHENTICATE          = 40
	WINHTTP_QUERY_PROXY_AUTHENTICATE        = 41
	WINHTTP_QUERY_ACCEPT_RANGES             = 42
	WINHTTP_QUERY_SET_COOKIE                = 43
	WINHTTP_QUERY_COOKIE                    = 44
	WINHTTP_QUERY_REQUEST_METHOD            = 45
	WINHTTP_QUERY_REFRESH                   = 46
	WINHTTP_QUERY_CONTENT_DISPOSITION       = 47
	WINHTTP_QUERY_AGE                       = 48
	WINHTTP_QUERY_CACHE_CONTROL             = 49
	WINHTTP_QUERY_CONTENT_BASE              = 50
	WINHTTP_QUERY_CONTENT_LOCATION          = 51
	WINHTTP_QUERY_CONTENT_MD5               = 52
	WINHTTP_QUERY_CONTENT_RANGE             = 53
	WINHTTP_QUERY_ETAG                      = 54
	WINHTTP_QUERY_HOST                      = 55
	WINHTTP_QUERY_IF_MATCH                  = 56
	WINHTTP_QUERY_IF_NONE_MATCH             = 57
	WINHTTP_QUERY_IF_RANGE                  = 58
	WINHTTP_QUERY_IF_UNMODIFIED_SINCE       = 59
	WINHTTP_QUERY_MAX_FORWARDS              = 60
	WINHTTP_QUERY_PROXY_AUTHORIZATION       = 61
	WINHTTP_QUERY_RANGE                     = 62
	WINHTTP_QUERY_TRANSFER_ENCODING         = 63
	WINHTTP_QUERY_UPGRADE                   = 64
	WINHTTP_QUERY_VARY                      = 65
	WINHTTP_QUERY_VIA                       = 66
	WINHTTP_QUERY_WARNING                   = 67
	WINHTTP_QUERY_EXPECT                    = 68
	WINHTTP_QUERY_PROXY_CONNECTION          = 69
	WINHTTP_QUERY_UNLESS_MODIFIED_SINCE     = 70
	WINHTTP_QUERY_PROXY_SUPPORT             = 75
	WINHTTP_QUERY_AUTHENTICATION_INFO       = 76
	WINHTTP_QUERY_PASSPORT_URLS             = 77
	WINHTTP_QUERY_PASSPORT_CONFIG           = 78
	WINHTTP_QUERY_MAX                       = 78
	WINHTTP_QUERY_CUSTOM                    = 65535
	WINHTTP_QUERY_FLAG_REQUEST_HEADERS      = 0x80000000
	WINHTTP_QUERY_FLAG_SYSTEMTIME           = 0x40000000
	WINHTTP_QUERY_FLAG_NUMBER               = 0x20000000

	WINHTTP_NO_OUTPUT_BUFFER = 0

	WINHTTP_NO_REFERER = ""

	WINHTTP_DEFAULT_ACCEPT_TYPES = ""

	WINHTTP_NO_REQUEST_DATA = 0

	WINHTTP_HEADER_NAME_BY_INDEX = ""

	WINHTTP_NO_HEADER_INDEX = 0

	// flags for WinHttp{Set/Query}Options
	WINHTTP_FIRST_OPTION                            = WINHTTP_OPTION_CALLBACK
	WINHTTP_OPTION_CALLBACK                         = 1
	WINHTTP_OPTION_RESOLVE_TIMEOUT                  = 2
	WINHTTP_OPTION_CONNECT_TIMEOUT                  = 3
	WINHTTP_OPTION_CONNECT_RETRIES                  = 4
	WINHTTP_OPTION_SEND_TIMEOUT                     = 5
	WINHTTP_OPTION_RECEIVE_TIMEOUT                  = 6
	WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT         = 7
	WINHTTP_OPTION_HANDLE_TYPE                      = 9
	WINHTTP_OPTION_READ_BUFFER_SIZE                 = 12
	WINHTTP_OPTION_WRITE_BUFFER_SIZE                = 13
	WINHTTP_OPTION_PARENT_HANDLE                    = 21
	WINHTTP_OPTION_EXTENDED_ERROR                   = 24
	WINHTTP_OPTION_SECURITY_FLAGS                   = 31
	WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT      = 32
	WINHTTP_OPTION_URL                              = 34
	WINHTTP_OPTION_SECURITY_KEY_BITNESS             = 36
	WINHTTP_OPTION_PROXY                            = 38
	WINHTTP_OPTION_PROXY_RESULT_ENTRY               = 39
	WINHTTP_OPTION_USER_AGENT                       = 41
	WINHTTP_OPTION_CONTEXT_VALUE                    = 45
	WINHTTP_OPTION_CLIENT_CERT_CONTEXT              = 47
	WINHTTP_OPTION_REQUEST_PRIORITY                 = 58
	WINHTTP_OPTION_HTTP_VERSION                     = 59
	WINHTTP_OPTION_DISABLE_FEATURE                  = 63
	WINHTTP_OPTION_CODEPAGE                         = 68
	WINHTTP_OPTION_MAX_CONNS_PER_SERVER             = 73
	WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER         = 74
	WINHTTP_OPTION_AUTOLOGON_POLICY                 = 77
	WINHTTP_OPTION_SERVER_CERT_CONTEXT              = 78
	WINHTTP_OPTION_ENABLE_FEATURE                   = 79
	WINHTTP_OPTION_WORKER_THREAD_COUNT              = 80
	WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT         = 81
	WINHTTP_OPTION_PASSPORT_COBRANDING_URL          = 82
	WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH          = 83
	WINHTTP_OPTION_SECURE_PROTOCOLS                 = 84
	WINHTTP_OPTION_ENABLETRACING                    = 85
	WINHTTP_OPTION_PASSPORT_SIGN_OUT                = 86
	WINHTTP_OPTION_PASSPORT_RETURN_URL              = 87
	WINHTTP_OPTION_REDIRECT_POLICY                  = 88
	WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS     = 89
	WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE         = 90
	WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE         = 91
	WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE          = 92
	WINHTTP_OPTION_CONNECTION_INFO                  = 93
	WINHTTP_OPTION_CLIENT_CERT_ISSUER_LIST          = 94
	WINHTTP_OPTION_SPN                              = 96
	WINHTTP_OPTION_GLOBAL_PROXY_CREDS               = 97
	WINHTTP_OPTION_GLOBAL_SERVER_CREDS              = 98
	WINHTTP_OPTION_UNLOAD_NOTIFY_EVENT              = 99
	WINHTTP_OPTION_REJECT_USERPWD_IN_URL            = 100
	WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS    = 101
	WINHTTP_OPTION_RECEIVE_PROXY_CONNECT_RESPONSE   = 103
	WINHTTP_OPTION_IS_PROXY_CONNECT_RESPONSE        = 104
	WINHTTP_OPTION_SERVER_SPN_USED                  = 106
	WINHTTP_OPTION_PROXY_SPN_USED                   = 107
	WINHTTP_OPTION_SERVER_CBT                       = 108
	WINHTTP_OPTION_UNSAFE_HEADER_PARSING            = 110
	WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS   = 111
	WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET            = 114
	WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT         = 115
	WINHTTP_OPTION_WEB_SOCKET_KEEPALIVE_INTERVAL    = 116
	WINHTTP_OPTION_DECOMPRESSION                    = 118
	WINHTTP_OPTION_WEB_SOCKET_RECEIVE_BUFFER_SIZE   = 122
	WINHTTP_OPTION_WEB_SOCKET_SEND_BUFFER_SIZE      = 123
	WINHTTP_OPTION_TCP_PRIORITY_HINT                = 128
	WINHTTP_OPTION_CONNECTION_FILTER                = 131
	WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL             = 133
	WINHTTP_OPTION_HTTP_PROTOCOL_USED               = 134
	WINHTTP_OPTION_KDC_PROXY_SETTINGS               = 136
	WINHTTP_OPTION_ENCODE_EXTRA                     = 138
	WINHTTP_OPTION_DISABLE_STREAM_QUEUE             = 139
	WINHTTP_OPTION_IPV6_FAST_FALLBACK               = 140
	WINHTTP_OPTION_CONNECTION_STATS_V0              = 141
	WINHTTP_OPTION_REQUEST_TIMES                    = 142
	WINHTTP_OPTION_EXPIRE_CONNECTION                = 143
	WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK = 144
	WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED           = 145
	WINHTTP_OPTION_REQUEST_STATS                    = 146
	WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT        = 147
	WINHTTP_LAST_OPTION                             = WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT
	WINHTTP_OPTION_USERNAME                         = 0x1000
	WINHTTP_OPTION_PASSWORD                         = 0x1001
	WINHTTP_OPTION_PROXY_USERNAME                   = 0x1002
	WINHTTP_OPTION_PROXY_PASSWORD                   = 0x1003

	SECURITY_FLAG_IGNORE_UNKNOWN_CA        = 0x00000100
	SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000
	SECURITY_FLAG_IGNORE_CERT_CN_INVALID   = 0x00001000
	SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  = 0x00000200
	SECURITY_FLAG_SECURE                   = 0x00000001
	SECURITY_FLAG_STRENGTH_WEAK            = 0x10000000
	SECURITY_FLAG_STRENGTH_MEDIUM          = 0x40000000
	SECURITY_FLAG_STRENGTH_STRONG          = 0x20000000

	WINHTTP_PROTOCOL_FLAG_HTTP1 = 0x0
	WINHTTP_PROTOCOL_FLAG_HTTP2 = 0x1
	WINHTTP_PROTOCOL_FLAG_HTTP3 = 0x2

	WINHTTP_FLAG_SECURE_PROTOCOL_SSL2   = 0x00000008
	WINHTTP_FLAG_SECURE_PROTOCOL_SSL3   = 0x00000020
	WINHTTP_FLAG_SECURE_PROTOCOL_TLS1   = 0x00000080
	WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 = 0x00000200
	WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800
	WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 = 0x00002000
	WINHTTP_FLAG_SECURE_PROTOCOL_ALL    = WINHTTP_FLAG_SECURE_PROTOCOL_SSL2 | WINHTTP_FLAG_SECURE_PROTOCOL_SSL3 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1

	WINHTTP_ADDREQ_FLAG_ADD_IF_NEW              = 0x10000000
	WINHTTP_ADDREQ_FLAG_ADD                     = 0x20000000
	WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA     = 0x40000000
	WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON = 0x01000000
	WINHTTP_ADDREQ_FLAG_COALESCE                = WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
	WINHTTP_ADDREQ_FLAG_REPLACE                 = 0x80000000
)

var winhttp = windows.NewLazySystemDLL("winhttp.dll")

// WinHttpOpen initializes, for an application, the use of WinHTTP functions and returns a WinHTTP-session handle.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen
//
// userAgent is a string that contains the name of the application or entity calling the WinHTTP functions.
// This name is used as the user agent in the HTTP protocol.
//
// accessType is the type of access required. This can be one of the following values:
//
//	WINHTTP_ACCESS_TYPE_NO_PROXY - Resolves all host names directly without a proxy
//	WINHTTP_ACCESS_TYPE_DEFAULT_PROXY - Important  Use of this option is deprecated on Windows 8.1 and newer.
//		Use WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY instead.
//	WINHTTP_ACCESS_TYPE_NAMED_PROXY - Passes requests to the proxy unless a proxy bypass list is supplied and the name
//		to be resolved bypasses the proxy. In this case, this function uses the values passed for pwszProxyName and pwszProxyBypass.
//	WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY - Uses system and per-user proxy settings (including the Internet Explorer proxy configuration)
//		to determine which proxy/proxies to use. Automatically attempts to handle failover between multiple proxies, different proxy
//		configurations per interface, and authentication. Supported in Windows 8.1 and newer.
//
// proxy is a string variable that contains the name of the proxy server to use when proxy access is specified by setting
//
//	dwAccessType to WINHTTP_ACCESS_TYPE_NAMED_PROXY. The WinHTTP functions recognize only CERN type proxies for HTTP.
//	If dwAccessType is not set to WINHTTP_ACCESS_TYPE_NAMED_PROXY, this parameter must be set to WINHTTP_NO_PROXY_NAME.
//
// proxyBypass is a string variable that contains an optional semicolon delimited list of host names or IP addresses, or both,
//
//	that should not be routed through the proxy when dwAccessType is set to WINHTTP_ACCESS_TYPE_NAMED_PROXY.
//	The list can contain wildcard characters. Do not use an empty string, because the WinHttpOpen function uses it as the proxy bypass list.
//	If this parameter specifies the "<local>" macro in the list as the only entry, this function bypasses any host name that does not contain
//	a period. If dwAccessType is not set to WINHTTP_ACCESS_TYPE_NAMED_PROXY, this parameter must be set to WINHTTP_NO_PROXY_BYPASS.
//
// flags contains the flags that indicate various options affecting the behavior of this function.
//
//	This parameter can have the following value:
//	WINHTTP_FLAG_ASYNC - Use the WinHTTP functions asynchronously.
//		By default, all WinHTTP functions that use the returned HINTERNET handle are performed synchronously.
//		When this flag is set, the caller needs to specify a callback function through WinHttpSetStatusCallback.
//	WINHTTP_FLAG_SECURE_DEFAULTS - When this flag is set, WinHttp will require use of TLS 1.2 or newer.
//		If the caller attempts to enable older TLS versions by setting WINHTTP_OPTION_SECURE_PROTOCOLS, it will fail with ERROR_ACCESS_DENIED.
//		Additionally, TLS fallback will be disabled. Note that setting this flag also sets flag WINHTTP_FLAG_ASYNC.
func WinHttpOpen(userAgent string, accessType int, proxy string, proxyBypass string, flags uint32) (windows.Handle, error) {
	slog.Debug("entering into WinHttpOpen function", "user-agent", userAgent, "accessType", accessType, "proxy", proxy, "proxyBypass", proxyBypass, "flags", flags)

	// Convert useragent to a wide string
	pszAgentW, err := windows.UTF16PtrFromString(userAgent)
	if err != nil {
		slog.Error("there was an error converting userAgent to a UTF16 pointer", "userAgent", userAgent, "error", err)
		return 0, fmt.Errorf("winhttp WinHttpOpen(): there was an error converting the userAgent value '%s' to a UTF16 pointer: %s", userAgent, err)
	}

	dwAccessType := uint32(accessType)

	// Convert proxy and proxyBypass to a wide string
	var pszProxyW *uint16
	var pszProxyBypassW *uint16
	if accessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY {
		p := uint16(WINHTTP_NO_PROXY_NAME)
		pszProxyW = &p
		slog.Debug("the access type was NOT set to WINHTTP_ACCESS_TYPE_NAMED_PROXY forcing proxy to be set to WINHTTP_NO_PROXY_NAME", "access type", accessType, "proxy", proxy)

		b := uint16(WINHTTP_NO_PROXY_BYPASS)
		pszProxyBypassW = &b
		slog.Debug("the access type was NOT set to WINHTTP_ACCESS_TYPE_NAMED_PROXY forcing proxyBypass to be set to WINHTTP_NO_PROXY_BYPASS", "access type", accessType, "proxyBypass", proxyBypass)
	} else {
		pszProxyW, err = windows.UTF16PtrFromString(proxy)
		if err != nil {
			slog.Error("there was an error converting proxy to a UTF16 pointer", "proxy", proxy, "error", err)
			return 0, fmt.Errorf("winhttp WinHttpOpen(): there was an error converting the proxy value '%s' to a UTF16 pointer: %s", proxy, err)
		}

		if proxyBypass != "" {
			pszProxyBypassW, err = windows.UTF16PtrFromString(proxyBypass)
			if err != nil {
				slog.Error("there was an error converting proxyBypass to a UTF16 pointer", "proxyBypass", proxyBypass, "error", err)
				return 0, fmt.Errorf("winhttp WinHttpOpen(): there was an error converting the proxyBypass value '%s' to a UTF16 pointer: %s", proxyBypass, err)
			}
		} else {
			b := uint16(WINHTTP_NO_PROXY_BYPASS)
			pszProxyBypassW = &b
		}
	}

	dwFlags := flags

	proc := winhttp.NewProc("WinHttpOpen")
	// WINHTTPAPI HINTERNET WinHttpOpen(
	//  [in, optional] LPCWSTR pszAgentW,
	//  [in]           DWORD   dwAccessType,
	//  [in]           LPCWSTR pszProxyW,
	//  [in]           LPCWSTR pszProxyBypassW,
	//  [in]           DWORD   dwFlags
	// );
	r, _, err := proc.Call(
		uintptr(unsafe.Pointer(pszAgentW)),
		uintptr(dwAccessType),
		uintptr(unsafe.Pointer(pszProxyW)),
		uintptr(unsafe.Pointer(pszProxyBypassW)),
		uintptr(dwFlags),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpOpen", "error", err)
		return 0, fmt.Errorf("winhttp WinHttpOpen(): there was an error calling winhttp!WinHttpOpen: %s", err)
	}
	if r == 0 {
		return 0, fmt.Errorf("the winhttp!WinHttpOpen function returned 0")
	}
	return windows.Handle(r), nil
}

// WinHttpConnect specifies the initial target server of an HTTP request and returns an
// HINTERNET connection handle to an HTTP session for that initial target.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect
//
// hSession is a valid HINTERNET WinHTTP session handle returned by a previous call to WinHttpOpen.
//
// serverName is a string that contains the host name of an HTTP server.
//
//	Alternately, the string can contain the IP address of the site in ASCII, for example, 10.0.1.45.
//	Note that WinHttp does not accept international host names without converting them first to Punycode
//
// serverPort is an unsigned integer that specifies the TCP/IP port on the server to which a connection is made.
//
//	This parameter can be any valid TCP/IP port number, or one of the following values:
//		INTERNET_DEFAULT_HTTP_PORT - INTERNET_DEFAULT_HTTP_PORT
//		INTERNET_DEFAULT_HTTPS_PORT - Uses the default port for HTTPS servers (port 443).
//			Selecting this port does not automatically establish a secure connection.
//			You must still specify the use of secure transaction semantics by using the WINHTTP_FLAG_SECURE flag with WinHttpOpenRequest.
//		INTERNET_DEFAULT_PORT - Uses port 80 for HTTP and port 443 for Secure Hypertext Transfer Protocol (HTTPS).
func WinHttpConnect(hSession windows.Handle, serverName string, serverPort uint32) (windows.Handle, error) {
	slog.Debug("entering into WinHttpConnect function", "session", hSession, "serverName", serverName, "serverPort", serverPort)

	// Convert server name to a LPCWSTR (uint16 pointer)
	pswzServerName, err := windows.UTF16PtrFromString(serverName)
	if err != nil {
		slog.Error("there was an error converting serverName to a UTF16 pointer", "serverName", serverName, "error", err)
		return 0, fmt.Errorf("winhttp WinHttpConnect(): there was an error converting the server name '%s' to a UTF16 pointer: %s", serverName, err)
	}

	nServerPort := serverPort

	proc := winhttp.NewProc("WinHttpConnect")
	// WINHTTPAPI HINTERNET WinHttpConnect(
	//	[in] HINTERNET     hSession,
	//	[in] LPCWSTR       pswzServerName,
	//	[in] INTERNET_PORT nServerPort,
	//	[in] DWORD         dwReserved
	// );
	r, _, err := proc.Call(
		uintptr(hSession),
		uintptr(unsafe.Pointer(pswzServerName)),
		uintptr(nServerPort),
		0,
	)

	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpConnect", "error", err)
		return 0, fmt.Errorf("there was an error calling winhttp!WinHttpConnect: %s", err)
	}
	if r == 0 {
		return 0, fmt.Errorf("the winhttp!WinHttpConnect function returned 0")
	}
	return windows.Handle(r), nil
}

// WinHttpOpenRequest creates an HTTP request handle
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopenrequest
//
// hConnect is a connection handle to an HTTP session returned by WinHttpConnect
//
// method is a string that contains the HTTP verb to use in the request. If this parameter is empty, the function uses GET as the HTTP verb
//
// path is a string that contains the name of the target resource of the specified HTTP verb. This is generally a file name, an executable module, or a search specifier.
//
// version is a string that contains the HTTP version. If this parameter is empty, the function uses HTTP/1.1.
//
// referrer a string that specifies the URL of the document from which the URL in the request pwszObjectName was obtained.
//
//	If this parameter is set to WINHTTP_NO_REFERER, no referring document is specified
//
// acceptTypes an array of strings that specifies media types accepted by the client.
//
//	If this parameter is set to WINHTTP_DEFAULT_ACCEPT_TYPES, no types are accepted by the client.
//	Typically, servers handle a lack of accepted types as indication that the client accepts only documents of type "text/*";
//	that is, only text documents—no pictures or other binary files. For a list of valid media types, see Media Types defined
//	by IANA at http://www.iana.org/assignments/media-types/
//
// flags contains the Internet flag values. This can be one or more of the following values:
//
//	WINHTTP_FLAG_BYPASS_PROXY_CACHE - This flag provides the same behavior as WINHTTP_FLAG_REFRESH.
//	WINHTTP_FLAG_ESCAPE_DISABLE - Unsafe characters in the URL passed in for pwszObjectName are not converted to escape sequences.
//	WINHTTP_FLAG_ESCAPE_DISABLE_QUERY - Unsafe characters in the query component of the URL passed in for pwszObjectName are not converted to escape sequences.
//	WINHTTP_FLAG_ESCAPE_PERCENT - The string passed in for pwszObjectName is converted from an LPCWSTR to an LPSTR. All unsafe characters are converted to an
//		escape sequence including the percent symbol. By default, all unsafe characters except the percent symbol are converted to an escape sequence.
//	WINHTTP_FLAG_NULL_CODEPAGE - The string passed in for pwszObjectName is assumed to consist of valid ANSI characters represented by WCHAR.
//		No check are done for unsafe characters.
//		Windows 7:  This option is obsolete.
//	WINHTTP_FLAG_REFRESH - Indicates that the request should be forwarded to the originating server rather than sending a cached version of a resource from a proxy server.
//		 When this flag is used, a "Pragma: no-cache" header is added to the request handle. When creating an HTTP/1.1 request header, a "Cache-Control: no-cache" is also added.
//	WINHTTP_FLAG_SECURE - Uses secure transaction semantics. This translates to using Secure Sockets Layer (SSL)/Transport Layer Security (TLS).
func WinHttpOpenRequest(hConnect windows.Handle, method string, path string, version string, referrer string, accessTypes []string, flags uint32) (windows.Handle, error) {
	slog.Debug("entering into WinHttpOpenRequest function", "hConnect", hConnect, "method", method, "path", path, "version", version, "referrer", referrer, "accessTypes", accessTypes, "flags", flags)

	// Convert HTTP method to LPCWSTR
	pwszVerb, err := windows.UTF16PtrFromString(strings.ToUpper(method))
	if err != nil {
		slog.Error("there was an error converting method to a UTF16 pointer", "method", method, "error", err)
		return 0, fmt.Errorf("winhttp WinHttpOpenRequest(): there was an error converting the HTTP method '%s' to a UTF16 pointer: %s", method, err)
	}

	// Convert the URI to LPCWSTR
	pwszObjectName, err := windows.UTF16PtrFromString(path)
	if err != nil {
		slog.Error("there was an error converting path to a UTF16 pointer", "path", path, "error", err)
		return 0, fmt.Errorf("winhttp WinHttpOpenRequest(): there was an error converting the path '%s' to a UTF16 pointer: %s", path, err)
	}

	// Convert the version to LPCWSTR
	var pwszVersion *uint16
	if version == "" {
		NULL := uint16(0)
		pwszVersion = &NULL
	} else {
		pwszVersion, err = windows.UTF16PtrFromString(version)
		if err != nil {
			slog.Error("there was an error converting version to a UTF16 pointer", "version", version, "error", err)
			return 0, fmt.Errorf("winhttp WinHttpOpenRequest(): there was an error converting the version '%s' to a UTF16 pointer: %s", version, err)
		}
	}

	// Convert the version to LPCWSTR
	pwszReferrer, err := windows.UTF16PtrFromString(referrer)
	if err != nil {
		slog.Error("there was an error converting referrer to a UTF16 pointer", "referrer", referrer, "error", err)
		return 0, fmt.Errorf("winhttp WinHttpOpenRequest(): there was an error converting the referrer '%s' to a UTF16 pointer: %s", referrer, err)
	}

	// convert acceptTypes to LPCWSTR
	// Pointer to a null-terminated array of string pointers that specifies media types accepted by the client
	var ppwszAcceptTypes []*uint16
	if len(accessTypes) > 0 {
		for i, acceptType := range accessTypes {
			var pwszAcceptType *uint16
			// An empty string will cause the Accept header to be added to the request with no value
			if acceptType == "" {
				if i == 0 {
					ppwszAcceptTypes = []*uint16{nil}
					continue
				}
				// Adding an empty string to the array causes it to be null-terminated in that spot
				// and the rest of the array is ignored. So we just break out of the loop here.
				continue
			}
			pwszAcceptType, err = windows.UTF16PtrFromString(acceptType)
			if err != nil {
				slog.Error("there was an error converting acceptType to a UTF16 pointer", "acceptType", acceptType, "error", err)
				return 0, fmt.Errorf("winhttp WinHttpOpenRequest(): there was an error converting the acceptType '%s' to a UTF16 pointer: %s", acceptType, err)
			}
			ppwszAcceptTypes = append(ppwszAcceptTypes, pwszAcceptType)
		}
	} else {
		ppwszAcceptTypes = []*uint16{nil}
	}

	dwFlags := flags

	winhttpopenrequest := winhttp.NewProc("WinHttpOpenRequest")
	// WINHTTPAPI HINTERNET WinHttpOpenRequest(
	//	[in] HINTERNET hConnect,
	//	[in] LPCWSTR   pwszVerb,
	//	[in] LPCWSTR   pwszObjectName,
	//	[in] LPCWSTR   pwszVersion,
	//	[in] LPCWSTR   pwszReferrer,
	//	[in] LPCWSTR   *ppwszAcceptTypes,
	//	[in] DWORD     dwFlags
	// );
	r, _, err := winhttpopenrequest.Call(
		uintptr(hConnect),
		uintptr(unsafe.Pointer(pwszVerb)),
		uintptr(unsafe.Pointer(pwszObjectName)),
		uintptr(unsafe.Pointer(pwszVersion)),
		uintptr(unsafe.Pointer(pwszReferrer)),
		uintptr(unsafe.Pointer(&ppwszAcceptTypes[0])),
		uintptr(dwFlags),
	)

	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpOpenRequest", "error", err)
		return 0, fmt.Errorf("there was an error calling winhttp!WinHttpOpenRequest: %s", err)
	}
	if r == 0 {
		return 0, fmt.Errorf("the winhttp!WinHttpOpenRequest function returned 0")
	}

	return windows.Handle(r), nil
}

// WinHttpSendRequest sends the specified request to the HTTP server
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest
//
// hRequest is an HINTERNET handle returned by WinHttpOpenRequest.
//
// headers an string that contains the additional headers to append to the request.
//
//	This parameter can be WINHTTP_NO_ADDITIONAL_HEADERS if there are no additional headers to append.
//
// headersLength contains the length, in characters, of the additional headers.
//
//	If this parameter is -1L and pwszHeaders is not NULL, this function assumes that pwszHeaders is null-terminated, and the length is calculated.
//
// optionalData is a pointer a buffer that contains any optional data to send immediately after the request headers.
//
//	This parameter is generally used for POST and PUT operations.
//	The optional data can be the resource or data posted to the server.
//	This parameter can be WINHTTP_NO_REQUEST_DATA if there is no optional data to send.
//	If the dwOptionalLength parameter is 0, this parameter is ignored and set to NULL.
//	This buffer must remain available until the request handle is closed or the call to WinHttpReceiveResponse has completed.
//
// optionalDataLen is an unsigned long integer value that contains the length, in bytes, of the optional data.
//
//	This parameter can be zero if there is no optional data to send.
//	This parameter must contain a valid length when the lpOptional parameter is not NULL. Otherwise, lpOptional is ignored and set to NULL.
//
// totalLen is an unsigned long integer value that contains the length, in bytes, of the total data sent.
//
//	This parameter specifies the Content-Length header of the request.
//	If the value of this parameter is greater than the length specified by dwOptionalLength, then WinHttpWriteData can be used to send additional data.
//	dwTotalLength must not change between calls to WinHttpSendRequest for the same request.
//	If dwTotalLength needs to be changed, the caller should create a new request.
//
// context A pointer to a pointer-sized variable that contains an application-defined value that is passed, with the request handle, to any callback functions.
func WinHttpSendRequest(hRequest windows.Handle, headers string, headersLength uint32, optionalData uintptr, optionalDataLen uint32, totalLen uint32, context uintptr) error {
	slog.Debug("entering into WinHttpSendRequest function", "hRequest", hRequest, "headers", headers, "optioanlData", optionalData, "optionalDataLen", optionalDataLen, "totalLen", totalLen, "context", context)

	// Convert headers to LPCWSTR
	lpszHeaders, err := windows.UTF16PtrFromString(headers)
	if err != nil {
		slog.Error("there was an error converting headers to a UTF16 pointer", "headers", headers, "error", err)
		return fmt.Errorf("winhttp WinHttpSendRequest(): there was an error converting the headers '%s' to a UTF16 pointer: %s", headers, err)
	}

	dwHeadersLength := headersLength

	lpOptional := optionalData
	dwOptionalLength := optionalDataLen
	dwTotalLength := totalLen
	dwContext := context

	proc := winhttp.NewProc("WinHttpSendRequest")
	// WINHTTPAPI BOOL WinHttpSendRequest(
	//	[in]           HINTERNET hRequest,
	//	[in, optional] LPCWSTR   lpszHeaders,
	//	[in]           DWORD     dwHeadersLength,
	//	[in, optional] LPVOID    lpOptional,
	//	[in]           DWORD     dwOptionalLength,
	//	[in]           DWORD     dwTotalLength,
	//	[in]           DWORD_PTR dwContext
	// );
	r, _, err := proc.Call(
		uintptr(hRequest),
		uintptr(unsafe.Pointer(lpszHeaders)),
		uintptr(dwHeadersLength),
		lpOptional,
		uintptr(dwOptionalLength),
		uintptr(dwTotalLength),
		dwContext,
	)

	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpSendRequest", "error", err)
		return fmt.Errorf("winhttp there was an error calling winhttp!WinHttpSendRequest: %s", err)
	}
	// Returns TRUE if successful, or FALSE otherwise
	if r == 0 {
		return fmt.Errorf("the winhttp!WinHttpSendRequest function returned 0")
	}
	return nil
}

// WinHttpReceiveResponse waits to receive the response to an HTTP request initiated by WinHttpSendRequest.
// When WinHttpReceiveResponse completes successfully, the status code and response headers have been received and are available for
// the application to inspect using WinHttpQueryHeaders.
// An application must call WinHttpReceiveResponse before it can use WinHttpQueryDataAvailable and WinHttpReadData to access the
// response entity body (if any).
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreceiveresponse
//
// hRequest an HINTERNET handle returned by WinHttpOpenRequest and sent by WinHttpSendRequest.
//
//	Wait until WinHttpSendRequest has completed for this handle before calling WinHttpReceiveResponse.
func WinHttpReceiveResponse(hRequest windows.Handle) error {
	slog.Debug("entering into WinHttpReceiveResponse function", "hRequest", hRequest)
	proc := winhttp.NewProc("WinHttpReceiveResponse")
	// WINHTTPAPI BOOL WinHttpReceiveResponse(
	//	[in] HINTERNET hRequest,
	//	[in] LPVOID    lpReserved
	// );
	r, _, err := proc.Call(uintptr(hRequest), 0)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpReceiveResponse", "error", err)
		return fmt.Errorf("winhttp there was an error calling winhttp!WinHttpReceiveResponse: %s", err)
	}
	// Returns TRUE if successful, or FALSE otherwise
	if r == 0 {
		return fmt.Errorf("the winhttp!WinHttpReceiveResponse function returned 0")
	}
	return nil
}

// WinHttpReadData reads data from a handle opened by the WinHttpOpenRequest function.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata
//
// hRequest is a valid HINTERNET handle returned from a previous call to WinHttpOpenRequest.
// WinHttpReceiveResponse or WinHttpQueryDataAvailable must have been called for this handle
// and must have completed before WinHttpReadData is called.
// Although calling WinHttpReadData immediately after completion of WinHttpReceiveResponse avoids the expense
// of a buffer copy, doing so requires that the application use a fixed-length buffer for reading.
//
// size is the number of bytes to read
func WinHttpReadData(hRequest windows.Handle, size uint32) ([]byte, error) {
	slog.Debug("entering into WinHttpReadData function", "hRequest", hRequest, "size", size)
	// WinHttpQueryDataAvailable returns 0 when there is nothing left to read, but this function must be called to determine if finished
	// Size 0 buffer causes error
	if size == 0 {
		size = 1
	}

	lpBuffer := make([]byte, size)
	dwNumberOfBytesToRead := size
	lpdwNumberOfBytesRead := uint32(0)

	proc := winhttp.NewProc("WinHttpReadData")
	// WINHTTPAPI BOOL WinHttpReadData(
	//	[in]  HINTERNET hRequest,
	//	[out] LPVOID    lpBuffer,
	//	[in]  DWORD     dwNumberOfBytesToRead,
	//	[out] LPDWORD   lpdwNumberOfBytesRead
	// );
	r, _, err := proc.Call(
		uintptr(hRequest),
		uintptr(unsafe.Pointer(&lpBuffer[0])),
		uintptr(dwNumberOfBytesToRead),
		uintptr(unsafe.Pointer(&lpdwNumberOfBytesRead)),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpReadData", "error", err)
		return []byte{}, fmt.Errorf("there was an error calling winhttp!WinHttpReadData: %s", err)
	}
	// Returns TRUE if successful, or FALSE otherwise
	if r == 0 {
		return []byte{}, fmt.Errorf("the winhttp!WinHttpReadData function returned 0")
	}

	// If you are using WinHttpReadData synchronously, and the return value is TRUE and the number of bytes read is zero,
	// the transfer has been completed and there are no more bytes to read on the handle.
	if lpdwNumberOfBytesRead == 0 {
		return []byte{}, nil
	}

	return lpBuffer, nil
}

// WinHttpQueryDataAvailable returns the amount of data, in bytes, available to be read with WinHttpReadData.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpquerydataavailable
//
// hRequest a valid HINTERNET handle returned by WinHttpOpenRequest.
// WinHttpReceiveResponse must have been called for this handle and have completed before WinHttpQueryDataAvailable is called.
func WinHttpQueryDataAvailable(hRequest windows.Handle) (uint32, error) {
	slog.Debug("entering into WinHttpQueryDataAvailable function", "hRequest", hRequest)
	lpdwNumberOfBytesAvailable := uint32(0)

	proc := winhttp.NewProc("WinHttpQueryDataAvailable")
	// WINHTTPAPI BOOL WinHttpQueryDataAvailable(
	//	[in]  HINTERNET hRequest,
	//	[out] LPDWORD   lpdwNumberOfBytesAvailable
	// );
	r, _, err := proc.Call(
		uintptr(hRequest),
		uintptr(unsafe.Pointer(&lpdwNumberOfBytesAvailable)),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpQueryDataAvailable", "error", err)
		return lpdwNumberOfBytesAvailable, fmt.Errorf("there was an error calling winhttp!WinHttpQueryDataAvailable: %s", err)
	}
	// Returns TRUE if successful, or FALSE otherwise
	if r == 0 {
		return lpdwNumberOfBytesAvailable, fmt.Errorf("the winhttp!WinHttpQueryDataAvailable function returned 0")
	}
	return lpdwNumberOfBytesAvailable, nil
}

// WinHttpQueryHeaders retrieves header information associated with an HTTP request.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpqueryheaders
//
// hRequest is an HINTERNET request handle returned by WinHttpOpenRequest.
//
//	WinHttpReceiveResponse must have been called for this handle and have completed before WinHttpQueryHeaders is called.
//
// infoLevel specifies a combination of attribute and modifier flags listed on the Query Info Flags page.
// These attribute and modifier flags indicate that the information is being requested and how it is to be formatted.
// https://learn.microsoft.com/en-us/windows/win32/winhttp/query-info-flags
//
// header a string that contains the header name.
// If the flag in dwInfoLevel is not WINHTTP_QUERY_CUSTOM, set this parameter to WINHTTP_HEADER_NAME_BY_INDEX.
//
// index used to enumerate multiple headers with the same name.
// When calling the function, this parameter is the index of the specified header to return.
// When the function returns, this parameter is the index of the next header.
// If the next index cannot be found, ERROR_WINHTTP_HEADER_NOT_FOUND is returned.
// Set this parameter to WINHTTP_NO_HEADER_INDEX to specify that only the first occurrence of a header should be returned.
func WinHttpQueryHeaders(hRequest windows.Handle, infoLevel uint32, header string, index uint32) ([]byte, error) {
	slog.Debug("entering into WinHttpQueryHeaders function", "hRequest", hRequest, "info level", infoLevel, "header", header, "index", index)
	dwInfoLevel := infoLevel

	// lpBuffer is a pointer to the buffer that receives the information.
	// Setting this parameter to WINHTTP_NO_OUTPUT_BUFFER causes this function to return FALSE.
	// Calling GetLastError then returns ERROR_INSUFFICIENT_BUFFER and lpdwBufferLength contains the number of bytes required to hold the requested information.
	var lpBuffer []byte

	// lpdwBufferLength Pointer to a value of type DWORD that specifies the length of the data buffer, in bytes.
	// When the function returns, this parameter contains the pointer to a value that specifies the length of the information written to the buffer.
	// When the function returns strings, the following rules apply.
	// If the function succeeds, lpdwBufferLength specifies the length of the string, in bytes, minus 2 for the terminating null.
	// If the function fails and ERROR_INSUFFICIENT_BUFFER is returned, lpdwBufferLength specifies the number of bytes that the application must allocate to receive the string.
	var lpdwBufferLength int64

	// pwszName - Pointer to a string that contains the header name.
	// If the flag in dwInfoLevel is not WINHTTP_QUERY_CUSTOM, set this parameter to WINHTTP_HEADER_NAME_BY_INDEX.
	var pwszName *uint16
	var err error
	if header != "" {
		pwszName, err = windows.UTF16PtrFromString(header)
		if err != nil {
			slog.Error("there was an error converting the header string to a UTF16 pointer", "header", header, "error", err)
			return lpBuffer, fmt.Errorf("WinHttpQueryHeader there was an error converting '%s' to a LPCWSTR: %s", header, err)
		}
	}

	proc := winhttp.NewProc("WinHttpQueryHeaders")
	// WINHTTPAPI BOOL WinHttpQueryHeaders(
	//	[in]           HINTERNET hRequest,
	//	[in]           DWORD     dwInfoLevel,
	//	[in, optional] LPCWSTR   pwszName,
	//	[out]          LPVOID    lpBuffer,
	//	[in, out]      LPDWORD   lpdwBufferLength,
	//	[in, out]      LPDWORD   lpdwIndex
	// );

	// Call first time get the buffer size
	r, _, err := proc.Call(
		uintptr(hRequest),
		uintptr(dwInfoLevel),
		uintptr(unsafe.Pointer(pwszName)),
		WINHTTP_NO_OUTPUT_BUFFER,
		uintptr(unsafe.Pointer(&lpdwBufferLength)),
		uintptr(unsafe.Pointer(&index)),
	)
	// First run returns ERROR_INSUFFICIENT_BUFFER and lpdwBufferLength contains the number of bytes required to hold the requested information.
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		slog.Error("there was an error calling winhttp!WinHttpQueryHeaders with WINHTTP_NO_OUTPUT_BUFFER to determine the data size", "error", err)
		return lpBuffer, fmt.Errorf("winhttp there was an error calling winhttp!WinHttpQueryHeaders 1: %s", err)
	}
	// Returns TRUE (0) if successful, or FALSE (1) otherwise.
	// This one should return false with ERROR_INSUFFICIENT_BUFFER error and the lpdwBufferLength set
	if r == 1 {
		return lpBuffer, fmt.Errorf("the winhttp!WinHttpQueryHeaders function returned 1")
	}

	// Adjust the buffer size
	lpBuffer = make([]byte, lpdwBufferLength)

	// Call second time to get actual data
	r, _, err = proc.Call(
		uintptr(hRequest),
		uintptr(dwInfoLevel),
		uintptr(unsafe.Pointer(pwszName)),
		uintptr(unsafe.Pointer(&lpBuffer[0])),
		uintptr(unsafe.Pointer(&lpdwBufferLength)),
		uintptr(unsafe.Pointer(&index)),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winHttpQueryHeaders to receive the data", "error", err)
		return lpBuffer, fmt.Errorf("winhttp there was an error calling winhttp!WinHttpQueryHeaders 2: %s", err)
	}
	if r == 0 {
		return lpBuffer, fmt.Errorf("the winhttp!WinHttpQueryHeaders function returned 0")
	}
	return lpBuffer, nil
}

// WinHttpCloseHandle closes a single HINTERNET handle
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpclosehandle
//
// hInternet is a valid HINTERNET handle (see HINTERNET Handles in WinHTTP) to be closed.
// https://learn.microsoft.com/en-us/windows/win32/winhttp/hinternet-handles-in-winhttp
func WinHttpCloseHandle(hInternet windows.Handle) {
	slog.Debug("entering into WinHttpCloseHandle function", "hInternet", hInternet)
	proc := winhttp.NewProc("WinHttpCloseHandle")
	// // WINHTTPAPI BOOL WinHttpCloseHandle(
	//	[in] HINTERNET hInternet
	// );
	r, _, err := proc.Call(uintptr(hInternet))
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpCloseHandle", "error", err)
		return
	}
	// Returns TRUE if the handle is successfully closed, otherwise FALSE
	if r != 1 {
		slog.Error("winhttp!WinHttpCloseHandle returned something other than TRUE", "return", r)
	}
}

// WinHttpSetOption set an internal option
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsetoption
//
// hInternet is the HINTERNET handle on which to set data.
// Be aware that this can be either a Session handle or a Request handle, depending on what option is being set.
// For more information about how to determine which handle is appropriate to use in setting a particular option, see the Option Flags.
//
// option contains the Internet option to set. This can be one of the Option Flags values.
// https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags
//
// buffer a pointer to a buffer that contains the option setting.
//
// size contains the length of the buffer.
// The length of the buffer is specified in characters for the following options;
// for all other options, the length is specified in bytes.
func WinHttpSetOption(hInternet windows.Handle, option uint32, buffer []byte) error {
	slog.Debug("entering into WinHttpSetOption function", "hInternet", hInternet, "option", option, "buffer", fmt.Sprintf("(%d) 0x%X", len(buffer), buffer))
	dwOption := option
	lpBuffer := buffer
	dwBufferLength := uint32(len(buffer))

	proc := winhttp.NewProc("WinHttpSetOption")
	// WINHTTPAPI BOOL WinHttpSetOption(
	//	[in] HINTERNET hInternet,
	//	[in] DWORD     dwOption,
	//	[in] LPVOID    lpBuffer,
	//	[in] DWORD     dwBufferLength
	//  );
	r, _, err := proc.Call(
		uintptr(hInternet),
		uintptr(dwOption),
		uintptr(unsafe.Pointer(&lpBuffer[0])),
		uintptr(dwBufferLength),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpSetOption", "option", option, "buffer", fmt.Sprintf("0x%X", buffer), "error", err)
		return fmt.Errorf("winhttp there was an error calling winhttp!WinHttpSetOption: %s", err)
	}
	// Returns TRUE if the handle is successfully closed, otherwise FALSE
	if r == 0 {
		return fmt.Errorf("the winhttp!WinHttpSetOption function returned 0")
	}
	return nil
}

// WinHttpAddRequestHeaders adds one or more HTTP request headers to the HTTP request handle.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpaddrequestheaders
//
// hRequest is a valid HINTERNET request handle returned by WinHttpOpenRequest.
//
// headers a string that contains the headers to add to the request.
// Each header except the last must be terminated by a carriage return/line feed (CR/LF).
//
// modifiers the flags used to modify the semantics of this function.
// Can be one or more of the following flags:
// WINHTTP_ADDREQ_FLAG_ADD - Adds the header if it does not exist. Used with WINHTTP_ADDREQ_FLAG_REPLACE.
// WINHTTP_ADDREQ_FLAG_ADD_IF_NEW - Adds the header only if it does not already exist; otherwise, an error is returned.
// WINHTTP_ADDREQ_FLAG_COALESCE - Merges headers of the same name.
// WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA - Merges headers of the same name using a comma. For example, adding "Accept: text/*" followed by "Accept: audio/*" with this flag results in a single header "Accept: text/*, audio/*". This causes the first header found to be merged. The calling application must to ensure a cohesive scheme with respect to merged and separate headers.
// WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON - Merges headers of the same name using a semicolon.
// WINHTTP_ADDREQ_FLAG_REPLACE - Replaces or removes a header. If the header value is empty and the header is found, it is removed. If the value is not empty, it is replaced.
func WinHttpAddRequestHeaders(hRequest windows.Handle, headers string, modifiers uint32) error {
	slog.Debug("entering into WinHttpAddRequestHeaders function", "hRequest", hRequest, "headers", headers, "modifiers", fmt.Sprintf("%08b", modifiers))

	var lpszHeaders *uint16
	var err error
	// Convert the headers string to a UTF16 pointer
	if headers != "" {
		lpszHeaders, err = windows.UTF16PtrFromString(headers)
		if err != nil {
			slog.Error("there was an error converting the header string to a UTF16 pointer", "headers", headers, "error", err)
			return fmt.Errorf("WinHttpAddRequestHeaders there was an error converting '%s' to a LPCWSTR: %s", headers, err)
		}
	}

	dwHeadersLength := uint32(len(headers))
	dwModifiers := modifiers

	proc := winhttp.NewProc("WinHttpAddRequestHeaders")
	// WINHTTPAPI BOOL WinHttpAddRequestHeaders(
	//  [in] HINTERNET hRequest,
	//  [in] LPCWSTR   lpszHeaders,
	//  [in] DWORD     dwHeadersLength,
	//  [in] DWORD     dwModifiers
	// );
	r, _, err := proc.Call(
		uintptr(hRequest),
		uintptr(unsafe.Pointer(lpszHeaders)),
		uintptr(dwHeadersLength),
		uintptr(dwModifiers),
	)
	if !errors.Is(err, windows.ERROR_SUCCESS) {
		slog.Error("there was an error calling winhttp!WinHttpAddRequestHeaders", "headers", headers, "modifiers", fmt.Sprintf("%08b", modifiers), "error", err)
		return fmt.Errorf("winhttp there was an error calling winhttp!WinHttpAddRequestHeaders: %s", err)
	}
	// Returns TRUE if the handle is successfully closed, otherwise FALSE
	if r == 0 {
		return fmt.Errorf("the winhttp!WinHttpAddRequestHeaders function returned 0")
	}
	return nil
}
