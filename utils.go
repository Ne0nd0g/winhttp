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
	"fmt"
	"unicode/utf8"
)

// decodeUTF8 decodes a UTF8 string and returns it, removing null characters
func decodeUTF8(b []byte) (string, error) {
	if !utf8.Valid(b) {
		return "", fmt.Errorf("invalid UTF8: '0x%x'", b)
	}

	var s string

	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		// Exclude null bytes
		// For example U+3400 = '4' but is returned as two runes: '34' and '00'
		if r != rune(00) {
			s += string(r)
		}
		// Update the byte slice to start after this rune
		b = b[size:]
	}
	return s, nil
}
