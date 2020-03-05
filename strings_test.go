package irc

import "testing"

func TestStr(t *testing.T) {
	for _, x := range []struct {
		s, expect string
		transform func(string) string
	}{
		{`foo`, `foo`, ToLowerASCII},
		{`foo`, `foo`, ToLowerRFC1459},
		{`foo`, `foo`, ToLowerStrictRFC1459},
		{`x ASCII FfZz[]\{}|^~`, `x ascii ffzz[]\{}|^~`, ToLowerASCII},
		{`x RFC1459 FfZz[]\{}|^~`, `x rfc1459 ffzz{}|{}|~~`, ToLowerRFC1459},
		{`x StrictRFC1459 FfZz[]\{}|^~`, `x strictrfc1459 ffzz{}|{}|^~`, ToLowerStrictRFC1459},
	} {
		if x.transform(x.s) != x.expect {
			t.Fatalf("Failed: %+v got %q", x, x.transform(x.s))
		}
	}
}
