module github.com/stdchat/irc

go 1.13

require (
	github.com/go-irc/irc v2.1.0+incompatible
	github.com/stretchr/testify v1.5.1 // indirect
	golang.org/x/net v0.0.0-20191116160921-f9c825593386
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	gopkg.in/yaml.v2 v2.2.7 // indirect
	stdchat.org v0.0.0-20200304031717-ddf2b2bcd739
)

replace github.com/json-iterator/go => github.com/millerlogic/json-iterator-go v1.1.9-0.20191118175040-6551bfde9b40
