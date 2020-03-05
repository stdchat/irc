package irc

import "testing"

func TestInsertPrefix(t *testing.T) {
	allPrefixesOrder := "@%+"
	list := [][2]string{
		{"x", ""},
		{"%", "%"},
		{"%", "%"},
		{"@", "@%"},
		{"x", "@%"},
		{"+", "@%+"},
		{"+", "@%+"},
		{"%", "@%+"},
		{"@", "@%+"},
		{"x", "@%+"},
	}
	toPrefixes := ""
	for i, x := range list {
		expect := x[1]
		toPrefixes = insertPrefix(toPrefixes, x[0][0], allPrefixesOrder)
		if toPrefixes != expect {
			t.Errorf("[%d] expected '%s' got '%s'", i, expect, toPrefixes)
		}
	}
}
