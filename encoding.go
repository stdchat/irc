// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package irc

import (
	"strings"
	"unicode/utf8"
)

// This was chosen to be long enough to be a minimum-ish maximum trailing irc param.
// Consider default total max 510 with:
// 	:longPrefix PRIVMSG #longDest :ircLongMsg
// Even if it's too short, it still gives room to get a consensus on the encoding.
const ircLongMsg = 350

// Convert data from the server to valid UTF-8.
// Ideally do not use this for outgoing data, prefer to use UTF-8.
func ircToString(ircData string) string {
	s := ircData
	if len(s) >= ircLongMsg {
		// If it's a "long" string, see if it ends with broken utf8.
		// This can happen due to the server truncating a message in a bad place.
		// We don't want this case alone to reinterpret the whole message.
		endseq := 0
		for i := len(s) - 1; ; i-- {
			if i < 0 {
				endseq = 0 // Didn't find rune start.
				break
			}
			endseq++
			if utf8.RuneStart(s[i]) {
				break
			}
			if s[i]&0xC0 != 0x80 {
				endseq = 0 // It doesn't match utf8 or it's ASCII.
				break
			}
		}
		if endseq > 0 && endseq < utf8.UTFMax && !utf8.ValidString(s[len(s)-endseq:]) {
			// It's not valid and it's obviously not too long to be truncated.
			// We'll just exclude this broken utf8 from the end.
			s = s[:len(s)-endseq]
		}
	}
	if utf8.ValidString(s) {
		return s
	}
	return latin1toUTF8(ircData) // Use original input.
}

// Prefer to use ircToString above.
func latin1toUTF8(s string) string {
	buf := strings.Builder{}
	buf.Grow(len(s) + len(s)/8 + 2)
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x80 {
			buf.WriteByte((b >> 6) | 0xC0)
			buf.WriteByte((b & 0x3F) | 0x80)
		} else {
			buf.WriteByte(b)
		}
	}
	return buf.String()
}
