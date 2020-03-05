// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package irc

func lowerascii(ch byte) byte {
	if ch >= 'A' && ch <= 'Z' {
		return 'a' + ((ch) - 'A')
	}
	return ch
}

func lower1459(ch byte) byte {
	// {}|~ are the lowercase of []\^
	if ch >= 'A' && ch <= '^' {
		return 'a' + ((ch) - 'A')
	}
	return ch
}

func lower1459strict(ch byte) byte {
	// {}| are the lowercase of []\
	if ch >= 'A' && ch <= ']' {
		return 'a' + ((ch) - 'A')
	}
	return ch
}

func strbytetransform(s string, trans func(byte) byte) string {
	var buf []byte
	for i := 0; i < len(s); i++ {
		x := trans(s[i])
		if buf != nil {
			buf[i] = x
		} else if x != s[i] {
			buf = make([]byte, len(s))
			copy(buf[:i], s[:i])
			buf[i] = x
		}
	}
	if buf != nil {
		return string(buf)
	}
	return s
}

func ToLowerASCII(s string) string {
	return strbytetransform(s, lowerascii)
}

func ToLowerRFC1459(s string) string {
	return strbytetransform(s, lower1459)
}

func ToLowerStrictRFC1459(s string) string {
	return strbytetransform(s, lower1459strict)
}

func GetToLowerFunc(casemapping string) func(string) string {
	switch casemapping {
	case "ascii":
		return ToLowerASCII
	case "strict-rfc1459":
		return ToLowerStrictRFC1459
	default:
		return ToLowerRFC1459
	}
}
