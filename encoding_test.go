package irc

import (
	"strings"
	"testing"
)

func TestIRCEncoding(t *testing.T) {
	for i, x := range encIRCTest {
		input := x[0]
		expect := x[1]
		got := ircToString(input)
		if got != expect {
			t.Errorf("[%d] expected '%s' got '%s'", i, expect, got)
		}
	}
}

var encIRCLong1 = strings.Repeat(".", ircLongMsg)
var encIRCLong2 = strings.Repeat("\xC2\xB7", ircLongMsg/2) +
	strings.Repeat(".", ircLongMsg%2)

var encIRCTest = [][2]string{
	// input, expect
	{"", ""},
	{"foo bar", "foo bar"},
	{"\xE2\x98\x83", "☃"},
	{"\xC2\xB7", "·"},
	{"\xCA\xF1\xE7 :\xDE", "Êñç :Þ"},
	{"Êñç :Þ", "Êñç :Þ"},
	{encIRCLong1, encIRCLong1},
	{encIRCLong1 + "foo bar", encIRCLong1 + "foo bar"},
	{encIRCLong1 + "Êñç :Þ", encIRCLong1 + "Êñç :Þ"},
	{encIRCLong1 + "\xE2\x98", encIRCLong1}, // last seq truncated
	{encIRCLong2, encIRCLong2},
	{encIRCLong2 + "foo bar", encIRCLong2 + "foo bar"},
	{encIRCLong2 + "Êñç :Þ", encIRCLong2 + "Êñç :Þ"},
	{encIRCLong2 + "\xE2\x98", encIRCLong2}, // last seq truncated
}
