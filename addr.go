// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package irc

import (
	"errors"
	"net/url"
	"strings"
)

// s can be:
//  host = default port
//  host:port = use these.
//  host:+port = use TLS on port.
//  host:+ = use default TLS port.
//  irc://host = default port
//  irc://host:port = use these.
//  ircs://host:port = use TLS on port.
//  ircs://host = use default TLS port
// The URL forms can also end with /channel to join the channel.
func parseAddr(s string) (serverName, serverPort, join string, wantTLS bool, err error) {
	// https://www.w3.org/Addressing/draft-mirashi-url-irc-01.txt
	// https://tools.ietf.org/html/draft-butcher-irc-url-04
	// TODO: support ?key=channelkey
	var scheme, hostname, port, path string
	if strings.IndexByte(s, '/') == -1 {
		ilcolon := strings.LastIndexByte(s, ':')
		if strings.LastIndexByte(s, ']') < ilcolon {
			hostname = s[:ilcolon]
			port = s[ilcolon+1:]
		} else {
			hostname = s
		}
	} else {
		u, err2 := url.Parse(s)
		if err2 != nil {
			err = err2
			return
		}
		scheme = u.Scheme
		hostname = u.Hostname()
		port = u.Port()
		path = u.Path
	}
	if hostname == "" {
		err = errors.New("hostname expected")
		return
	}
	const defPort = "6667"
	const defTLSPort = "6697"
	switch scheme {
	case "irc", "":
		if port == "" {
			port = defPort
		}
		if port[0] == '+' {
			wantTLS = true
			port = port[1:]
			if port == "" {
				port = defTLSPort
			}
		} else {
			// https://tools.ietf.org/html/rfc7194
			wantTLS = port == defTLSPort || port == "7070"
		}
	case "ircs":
		wantTLS = true
		if port == "" {
			port = defTLSPort
		}
	default:
		err = errors.New("unexpected protocol")
		return
	}
	serverName = hostname
	serverPort = port
	after := strings.TrimPrefix(path, "/")
	pparts := strings.Split(after, ",")
	if len(pparts) > 0 {
		ischan := true
		for _, p := range pparts {
			if p == "isnick" || p == "isuser" {
				ischan = false
			}
		}
		if ischan {
			join = pparts[0]
			if join != "" {
				switch join[0] {
				case '#', '&', '+':
				default:
					join = "#" + join
				}
			}
		}
	}
	return
}
