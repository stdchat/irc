// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package irc

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/go-irc/irc"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
	"stdchat.org"
	"stdchat.org/service"
)

const Protocol = "irc"

type Client struct {
	sendLine     chan<- string
	mx           sync.RWMutex
	support      isupport            // locked by mx
	strToLower   func(string) string // locked by mx
	tp           service.Transporter
	conn         net.Conn
	svc          *service.Service
	lim          *rate.Limiter
	lastRecvTime time.Time // locked by mx
	addrs        []string
	nicks        []string
	realName     string
	user         string // user/ident
	pass         string // server pass
	version      string
	tlsConfig    *tls.Config
	requestCaps  []string
	channels     []*Channel    // locked by mx
	nick         string        // locked by mx. current nick, empty before 001.
	fixNick      chan struct{} // locked by mx
	netID        string
	recvLoopCh   chan cconn
	sendLoopCh   chan cconn
	done         chan struct{}
	disconnA     atomic.Value // atomic: chan struct{}, closed on single disconnect.
	connID       string       // locked by mx
	connState    int32        // atomic: connState*
	state        int32        // atomic: state*
	inick        int32        // atomic: nicks[inick%len] or -1
	Verbose      bool         // verbose output to log.Print/Printf
	forceTLS     int8         // 0 = default, 1 = force TLS, -1 = force not TLS.
}

const (
	stateInit = iota
	stateStarted
	stateReady  // started+ready
	stateClosed // Close was called.
)

func (client *Client) getState() int32 {
	return atomic.LoadInt32(&client.state)
}

func (client *Client) disconn() chan struct{} {
	ch, _ := client.disconnA.Load().(chan struct{})
	return ch
}

type cconn struct {
	conn    net.Conn
	disconn chan struct{}
}

type isupport map[string]string

func (support isupport) Int(key string) int {
	x, _ := strconv.ParseInt(key, 10, 64)
	return int(x)
}

func (support isupport) IsSet(key string) bool {
	_, ok := support[key]
	return ok
}

func (support isupport) clone() isupport {
	x := isupport{}
	for k, v := range support {
		x[k] = v
	}
	return x
}

var defaultSupport = isupport{
	"PREFIX":      "(ov)@+",
	"CHANTYPES":   "#&",
	"CHANMODES":   "be,k,l,imnpst",
	"CASEMAPPING": "rfc1459",
	"MODES":       "3",
	"NICKLEN":     "9",
}

// ServerTimeFormat is the time format of the server-time CAP.
// The time must be in UTC.
// ISO 8601: YYYY-MM-DDThh:mm:ss.sssZ
const ServerTimeFormat = "2006-01-02T15:04:05.999Z07:00"

func split(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == ';'
	})
}

func NewClient(svc *service.Service, addr, nick, pass string, values stdchat.ValuesInfo) (service.Networker, error) {
	if svc.Closed() {
		return nil, errors.New("service is closed")
	}

	addrs := split(addr)
	if len(addrs) == 0 {
		return nil, errors.New("address expected")
	}

	nicks := split(nick)
	if len(nicks) == 0 {
		return nil, errors.New("nickname expected")
	}

	user := values.Get("irc.user")
	if user == "" {
		user = nicks[0]
	}
	realName := values.Get("irc.real-name")
	if realName == "" {
		realName = user
	}

	sendLine := make(chan string, 32)
	client := &Client{
		sendLine:   sendLine,
		Verbose:    svc.Verbose,
		support:    defaultSupport,
		tp:         svc.Transporter(),
		svc:        svc,
		lim:        rate.NewLimiter(0.5, 4),
		recvLoopCh: make(chan cconn, 1),
		sendLoopCh: make(chan cconn, 1),
		done:       make(chan struct{}),
		addrs:      addrs,
		nicks:      nicks,
		realName:   realName,
		user:       user,
		pass:       pass,
	}
	client.changedAllSupportUnlocked() // lock not needed in New
	err := client.setNetID()
	if err != nil {
		return nil, err
	}
	client.version = "irc 3000"
	client.tlsConfig = &tls.Config{}

	// ircs:// use TLS...
	acceptInvalidCert := values.Get("accept-invalid-cert") == "1"
	client.tlsConfig.InsecureSkipVerify = acceptInvalidCert

	client.requestCaps = append(client.requestCaps,
		"multi-prefix", "extended-join", "account-tag", "account-notify",
		"away-notify", "message-tags", "server-time", "echo-message",
		"draft/labeled-response", "batch", "invite-notify", "chghost",
		"userhost-in-names", "draft/setname")
	client.requestCaps = append(client.requestCaps,
		split(values.Get("irc.cap.request"))...)

	if clientCert := values.Get("irc.tls.client-cert"); clientCert != "" {
		var certificate tls.Certificate
		for data := []byte(clientCert); ; {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			switch block.Type {
			case "RSA PRIVATE KEY":
				if certificate.PrivateKey != nil {
					return nil, errors.New("multiple private keys found in client cert")
				}
				var err error
				certificate.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					log.Printf("ERROR with TLS client cert PKCS1PrivateKey: %v", err)
				}
			case "PRIVATE KEY":
				if certificate.PrivateKey != nil {
					return nil, errors.New("multiple private keys found in client cert")
				}
				privKeyX, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					log.Printf("ERROR with TLS client cert PKCS8PrivateKey: %v", err)
				}
				if privKey, _ := privKeyX.(*rsa.PrivateKey); privKey == nil {
					log.Printf("ERROR with TLS client cert: not RSA private key")
				} else {
					certificate.PrivateKey = privKey
				}
			case "CERTIFICATE":
				certificate.Certificate = append(certificate.Certificate, block.Bytes)
				if certificate.Leaf == nil { // The first one is the leaf.
					if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
						log.Printf("ERROR with TLS client cert Certificate: %v", err)
					} else {
						certificate.Leaf = cert
					}
				}
			default:
				log.Printf("INFO unknown block in TLS client cert: %s", block.Type)
			}
		}
		if certificate.PrivateKey == nil {
			log.Println("INFO TLS client cert private key not found")
		}
		if len(certificate.Certificate) == 0 {
			log.Println("INFO TLS client cert certificate not found")
		}
		if certificate.PrivateKey == nil || len(certificate.Certificate) == 0 {
			return nil, errors.New("incomplete TLS client cert")
		}
		client.tlsConfig.Certificates = append(
			client.tlsConfig.Certificates, certificate)
		log.Println("Using TLS client cert")
	}

	if useTLS := values.Get("irc.use-tls"); useTLS == "1" {
		client.forceTLS = 1
	} else if useTLS == "0" {
		client.forceTLS = -1
	}

	go client.recvLoop()
	go client.sendLoop(sendLine)

	return client, nil
}

const (
	connStateInit = iota
	connStateConnecting
	connStateConnected
	connStateDisconnected
)

func (client *Client) getConnState() int32 {
	return atomic.LoadInt32(&client.connState)
}

// Connected returns true if a connection is established to the server.
func (client *Client) Connected() bool {
	return client.getConnState() == connStateConnected
}

// Closed returns true if Close() was called.
func (client *Client) Closed() bool {
	return client.getState() == stateClosed
}

// Ready returns true if we are logged onto the server and have a nickname.
func (client *Client) Ready() bool {
	return client.getState() == stateReady
}

func (client *Client) NetworkID() string {
	return client.netID
}

func (client *Client) ConnID() string {
	client.mx.RLock()
	connID := client.connID
	client.mx.RUnlock()
	return connID
}

// Nick gets your current nickname,
// which can be empty before or during a connection.
// Note that reading the Nick() may return the old nickname until updated by the server.
func (client *Client) Nick() string {
	client.mx.RLock()
	nick := client.nick
	client.mx.RUnlock()
	return nick
}

// NickID gets the ID of Nick()
func (client *Client) NickID() string {
	client.mx.RLock()
	defer client.mx.RUnlock()
	return client.strToLower(client.nick)
}

// SetNick sets your nickname. Also see Nick()
func (client *Client) SetNick(nick string) {
	atomic.StoreInt32(&client.inick, -1) // Custom nick; used by myNickChanged
	client.setNick(nick)
}

// SendLine queues up the line to be sent eventually, after considering rate limiting.
// Note that if the queue fills up, the call blocks; use TrySendLine to avoid this.
// An error can be returned when the connection is closed.
func (client *Client) SendLine(line string) error {
	select {
	case client.sendLine <- line:
		return nil
	case <-client.disconn():
		return errors.New("connection closed")
	}
}

var ErrSendQueueFull = errors.New("send queue full")

// TrySendLine is similar to SendLine,
// but will return ErrSendQueueFull immediately if the send queue is full.
func (client *Client) TrySendLine(line string) error {
	select {
	case client.sendLine <- line:
		return nil
	case <-client.disconn():
		return errors.New("connection closed")
	default:
		return ErrSendQueueFull
	}
}

func (client *Client) setNick(nick string) error {
	return client.SendLine("NICK :" + nick)
}

// Join IRC channels; joinArgs can have comma-separated names, and keys.
func (client *Client) Join(joinArgs string) error {
	return client.SendLine("JOIN " + joinArgs)
}

func (client *Client) SendMsg(dest, msg string) error {
	return client.SendLine("PRIVMSG " + dest + " :" + msg)
}

func (client *Client) SendAction(dest, msg string) error {
	return client.SendLine("PRIVMSG " + dest + " :\x01ACTION " + msg + "\x01")
}

func (client *Client) SendCTCP(dest, ctcp, args string) error {
	if args != "" {
		return client.SendMsg(dest, "\x01"+ctcp+" "+args+"\x01")
	} else {
		return client.SendMsg(dest, "\x01"+ctcp+"\x01")
	}
}

func (client *Client) SendNotice(dest, notice string) error {
	return client.SendLine("NOTICE " + dest + " :" + notice)
}

func (client *Client) SendCTCPReply(dest, ctcp, args string) error {
	if args != "" {
		return client.SendNotice(dest, "\x01"+ctcp+" "+args+"\x01")
	} else {
		return client.SendNotice(dest, "\x01"+ctcp+"\x01")
	}
}

func (client *Client) setNetID() error {
	for _, addr := range client.addrs {
		serverName, _, _, _, _ := parseAddr(addr)
		if serverName != "" {
			netID, err := publicsuffix.EffectiveTLDPlusOne(serverName)
			if err != nil {
				hostparts := strings.FieldsFunc(serverName,
					func(r rune) bool { return r == '.' })
				if len(hostparts) > 0 {
					netID := hostparts[len(hostparts)-1]
					n := len(netID)
					for i := len(hostparts) - 2; i >= 0; i-- {
						netID = hostparts[i] + "." + netID
						n += len(hostparts[i])
						if n > 5 {
							break
						}
					}
				}
			}
			if netID != "" {
				for i := 1; ; i++ {
					tryNetID := netID
					if i > 1 {
						//tryNetID += fmt.Sprintf(".%d", i)
						return errors.New("network already connected")
					}
					if client.svc.GetClientByNetwork(tryNetID) == nil {
						client.netID = tryNetID
						return nil
					}
				}
			}
		}
	}
	// Couldn't make a netID, so invent one.
	client.netID = service.MakeID("")
	return nil
}

func (client *Client) changedSupportUnlocked(key string) {
	switch key {
	case "CASEMAPPING":
		client.strToLower = GetToLowerFunc(client.support["CASEMAPPING"])
	}
}

func (client *Client) changedAllSupportUnlocked() {
	for k := range client.support {
		client.changedSupportUnlocked(k)
	}
}

// StringToLower converts s to lowercase per the server's casemapping.
func (client *Client) StringToLower(s string) string {
	client.mx.RLock()
	defer client.mx.RUnlock()
	return client.strToLower(s)
}

type chanMode byte

const (
	chanModeNone        chanMode = iota
	chanModeList                 // A
	chanModeAlwaysParam          // B
	chanModeSetParam             // C
	chanModeSetting              // D
)

func (x chanMode) Valid() bool {
	return x != 0
}

// isSet should be true if the arg is being set (+)
func (x chanMode) HasArg(isSet bool) bool {
	switch x {
	case chanModeList:
		return true
	case chanModeAlwaysParam:
		return true
	case chanModeSetParam:
		return isSet
	default:
		return false
	}
}

// Returns one of the chanMode* values above, chanModeNone (0) means not a chan mode.
func (client *Client) chanModeTypeUnlocked(mode byte) chanMode {
	itype := chanModeList
	chanmodes := client.support["CHANMODES"]
	for i := 0; i < len(chanmodes); i++ {
		ch := chanmodes[i]
		if ch == ',' {
			itype++
		} else if ch == mode {
			return itype
		}
	}
	// Now check PREFIX:
	prefix := client.support["PREFIX"]
	for i := 0; i < len(prefix); i++ {
		ch := prefix[i]
		if ch == ')' {
			break
		}
		if ch != '(' && ch == mode {
			return chanModeAlwaysParam
		}
	}
	return chanModeNone
}

func (client *Client) chanModeType(mode byte) chanMode {
	client.mx.RLock()
	defer client.mx.RUnlock()
	return client.chanModeTypeUnlocked(mode)
}

func (client *Client) NetworkName() string {
	client.mx.RLock()
	defer client.mx.RUnlock()
	netw := client.support["NETWORK"]
	if netw == "" {
		netw = client.netID
	}
	return netw
}

func (client *Client) GetStateInfo() service.ClientStateInfo {
	msg := stdchat.NetworkStateInfo{}
	msg.Type = "network-state"
	msg.Ready = client.Ready()
	msg.Network.Init(client.NetworkID(), "net")
	msg.Network.SetName(client.NetworkName(), "")
	msg.Connection.Init(client.ConnID(), "conn")
	msg.Myself.Init(client.NickID(), "user")
	msg.Myself.SetName(client.Nick(), "")
	msg.Protocol = Protocol
	if msg.Ready {
		client.setFeatures(&msg.Values)
	}
	client.mx.RLock()
	defer client.mx.RUnlock()
	var subs []stdchat.SubscriptionStateInfo
	for _, channel := range client.channels {
		if channel.joinedUnlocked() {
			subs = append(subs, channel.getStateInfoUnlocked(msg.Network))
		}
	}
	return service.ClientStateInfo{Network: msg, Subscriptions: subs}
}

func (client *Client) IsChanType(ch byte) bool {
	client.mx.RLock()
	defer client.mx.RUnlock()
	return strings.IndexByte(client.support["CHANTYPES"], ch) != -1
}

func (client *Client) IsNickPrefix(ch byte) bool {
	client.mx.RLock()
	defer client.mx.RUnlock()
	prefix := client.support["PREFIX"]
	iclose := strings.IndexByte(prefix, ')')
	if iclose != -1 {
		return strings.IndexByte(prefix[iclose+1:], ch) != -1
	}
	return false
}

func (client *Client) removeNickPrefixes(nick string) string {
	for len(nick) > 0 {
		if !client.IsNickPrefix(nick[0]) {
			break
		}
		nick = nick[1:]
	}
	return nick
}

func (client *Client) GetPrefix() (modes string, chars string) {
	client.mx.RLock()
	defer client.mx.RUnlock()
	prefix := client.support["PREFIX"]
	if len(prefix) > 0 && prefix[0] == '(' {
		x := prefix[1:]
		ix := strings.IndexByte(x, ')')
		if ix != -1 {
			modes = x[:ix]
			chars = x[ix+1:]
			return
		}
	}
	return
}

// Returns 0 if ch is not a channel nick prefix mode.
func (client *Client) GetNickPrefix(ch byte) byte {
	modes, chars := client.GetPrefix()
	ich := strings.IndexByte(modes, ch)
	if ich != -1 && ich < len(chars) {
		return chars[ich]
	}
	return 0
}

// get channel name, or empty if not.
func (client *Client) chanFromTarget(s string) string {
	s = client.removeNickPrefixes(s)
	if len(s) > 0 && client.IsChanType(s[0]) {
		return s
	}
	return ""
}

// Logout and Close.
// This is needed to release resources,
// stop goroutines, and remove from the service clients list.
func (client *Client) Logout(reason string) error {
	if !atomic.CompareAndSwapInt32(&client.state, stateStarted, stateClosed) &&
		!atomic.CompareAndSwapInt32(&client.state, stateReady, stateClosed) {
		if client.getState() == stateInit {
			return errors.New("not started")
		}
		return errors.New("already closed")
	}
	if client.Connected() {
		disconn := client.disconn()
		// Not closing the connection yet,
		// let the QUIT handle disconnect.
		if client.TrySendLine("QUIT :"+reason) != nil {
			client.disconnect("client closed")
		} else {
			// Not very patient...
			// TODO: use Shutdown context??
			select {
			case <-disconn:
			case <-time.After(5 * time.Second):
				client.disconnect("client closed")
			}
		}
	}
	client.svc.OnClientClosed(client)
	close(client.recvLoopCh)
	close(client.sendLoopCh)
	<-client.done
	return nil
}

// Close the client.
func (client *Client) Close() error {
	return client.Logout("Close")
}

// BreakConnection will force break the connection, as if there was a network error.
// A broken connection will auto-reconnect; use Close() for proper connection close.
func (client *Client) BreakConnection() error {
	client.mx.RLock()
	conn := client.conn
	client.mx.RUnlock()
	return conn.Close()
}

type doneCtx struct {
	context.Context
	done <-chan struct{}
}

func (ctx *doneCtx) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *doneCtx) Err() error {
	select {
	case <-ctx.done:
		return errors.New("Client is done")
	default:
		return nil
	}
}

func (ctx *doneCtx) String() string {
	return "Client context: " + Protocol
}

func (client *Client) Context() context.Context {
	return &doneCtx{context.Background(), client.done}
}

// The returned context is "done" when the current connection is closed,
// including on disconnection with auto-reconnect or client Close.
func (client *Client) connContext() context.Context {
	return &doneCtx{context.Background(), client.disconn()}
}

func (client *Client) maybeUnsubscribeAll(msgType string, m stdchat.MessageInfo) bool {
	// Clear channel members, send unsubscribe for all that had members.
	for _, channel := range client.GetChannels() {
		if channel.clearMembers() > 0 {
			client.publishUnsubscribe(channel, msgType, m, nil)
		}
	}
	return true
}

// This disconnect allows auto-reconnect; use Close to avoid reconnecting.
// Note: during disconnection, this can get called several times,
// only the first gets through, and thus only the first cause counts.
func (client *Client) disconnect(cause string) {
	if !atomic.CompareAndSwapInt32(&client.connState,
		connStateConnected, connStateDisconnected) {
		return
	}
	if cause == "" {
		cause = "disconnect"
	}

	// Not ready, but also not Close'd.
	atomic.CompareAndSwapInt32(&client.state, stateReady, stateStarted)

	var conn net.Conn
	func() {
		client.mx.Lock()
		defer client.mx.Unlock()
		// Do some lock things.
		conn = client.conn
		if client.fixNick != nil { // Don't try to fix nick.
			close(client.fixNick)
			client.fixNick = nil
		}
	}()

	close(client.disconn())
	conn.Close()

	{
		m := stdchat.MessageInfo{}
		m.SetText(cause)
		client.maybeUnsubscribeAll("unsubscribe", m)
	}
	{
		msg := &stdchat.NetMsg{}
		msg.Init(service.MakeID(""), "offline", Protocol,
			client.NetworkID())
		msg.Network.SetName(client.NetworkName(), "")
		client.tp.Publish(msg.Network.ID, "", "network", msg)
	}
	{
		msg := &stdchat.ConnMsg{}
		msg.Init(service.MakeID(""), "conn-state", Protocol,
			client.NetworkID(), client.ConnID(), stdchat.Disconnected)
		msg.Network.SetName(client.NetworkName(), "")
		msg.Cause = cause
		client.tp.Publish("", "", "conn", msg)
	}
	if !client.Closed() {
		// If not closed, it means we want to reconnect.
		go client.reconnect(client.Context(), "")
	}
}

func fixEncoding(e *irc.Message) {
	// Not bothering with Tags or Command.
	// Consciously decoding each parameter separately.
	for i := 0; i < len(e.Params); i++ {
		e.Params[i] = ircToString(e.Params[i])
	}
}

func (client *Client) recvLoop() {
	defer close(client.done)
	for {
		select {
		case cc, ok := <-client.recvLoopCh:
			if !ok {
				return
			}
			reader := bufio.NewReaderSize(cc.conn, 1024)
			for {
				// Loop quits when conn closed.
				line, err := reader.ReadString('\n')
				if err != nil {
					select {
					case <-cc.disconn:
						log.Printf("connection %s closed (recvLoop)", client.ConnID())
						//client.disconnect("connection closed")
					default:
						client.disconnect("read error")
					}
					break
				}
				e, err := irc.ParseMessage(line)
				if err != nil {
					//
					continue
				}
				fixEncoding(e)
				client.ircEvent(e)
			}
		}
	}
}

func (client *Client) sendLoop(sendLine <-chan string) {
	ctx := client.connContext()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
loop:
	for {

	drain: // Drain sendLine.
		for {
			select {
			case <-sendLine:
			default:
				break drain
			}
		}

		cc, ok := <-client.sendLoopCh
		if !ok {
			return
		}
		writer := cc.conn
		for {
			select {
			case <-cc.disconn:
				continue loop
			case line := <-sendLine:
				select { // Check again in case disconn is also ready.
				case <-cc.disconn:
					continue loop
				default:
				}
				line = cleanReplacer.Replace(line) // a "line" can't have newlines
				// As long as this wait is short, the ticker should be fine.
				if client.lim.Wait(ctx) == nil {
					if client.Verbose {
						log.Printf("-> %s", line)
					}
					_, err := writer.Write([]byte(line + "\r\n"))
					if err != nil {
						select {
						case <-cc.disconn:
							log.Printf("connection %s closed (sendLoop)", client.ConnID())
							//client.disconnect("connection closed")
						default:
							// This delay allows recvLoop potentially to do things first.
							// Note: this sleep plus client.lim.Wait need to be
							// less than the initial reconnect delay.
							// TODO: find a better way to do this.
							time.Sleep(100 * time.Millisecond)

							//client.tp.PublishError(service.MakeID(""), client.NetworkID(), err)
							// Not sending this error for reasons:
							// 1) After lim.Wait this error can surface way too late.
							// 2) On connection error, receive will find the problem.
							// For now, just log the error locally:
							log.Printf("Write error: %v", err)

							client.disconnect("write error")
						}
						continue loop
					}
					// Handle some outgoing commands:
					if strings.HasPrefix(line, "PRIVMSG ") ||
						strings.HasPrefix(line, "TAGMSG ") ||
						strings.HasPrefix(line, "NOTICE ") {
						// TODO: check for echo-message CAP...
						// If no echo-message CAP, feed our own through:
						if e, err := irc.ParseMessage(line); err != nil {
							log.Printf("WARN outgoing message failed to parse: %v", err)
						} else {
							e.Prefix.Name = client.Nick()
							msgid, _ := e.Tags.GetTag("msgid")
							if msgid == "" {
								msgid = service.MakeID("")
								e.Tags["msgid"] = irc.TagValue(msgid)
							}
							targets := strings.FieldsFunc(earg(e, 0), func(r rune) bool {
								return r == ','
							})
							if len(targets) < 2 {
								client.ircEvent(e)
							} else { // Split up the targets.
								for i, target := range targets {
									e2 := e.Copy()
									e2.Params[0] = target // Set single target.
									// Update the msgid to msgid@n:
									msgid2 := fmt.Sprintf("%s@%d", msgid, i+1)
									e2.Tags["msgid"] = irc.TagValue(msgid2)
									client.ircEvent(e2)
								}
							}
						}
					} else if line == "QUIT" || strings.HasPrefix(line, "QUIT ") {
						connID := client.ConnID()
						go func() {
							// Wait a short time for the server to respond.
							time.Sleep(time.Second)
							if connID == client.ConnID() { // Not if already reconnecting.
								client.disconnect("client quit")
							}
						}()
						continue loop
					}
				}
			case <-ticker.C:
				client.mx.RLock()
				lastRecvTime := client.lastRecvTime
				client.mx.RUnlock()
				if lastRecvTime.Add(1 * time.Minute).Before(time.Now()) {
					if lastRecvTime.Add(2 * time.Minute).Before(time.Now()) {
						client.disconnect("local ping timeout")
					} else {
						line := "PING :ping@" + client.ConnID()
						select {
						case client.sendLine <- line:
						default:
							// Ignore sending PING if the send queue is full,
							// it's already sending stuff and likely to get a response.
						}
					}
				}
			}
		}
	}
}

func (client *Client) Start(ctx context.Context, id string) error {
	if !atomic.CompareAndSwapInt32(&client.state, stateInit, stateStarted) {
		return errors.New("already started")
	}
	if !client.connect(client.Context(), id) {
		client.Close()
		return errors.New("too many failed attempts to connect")
	}
	return nil
}

func (client *Client) connect(ctx context.Context, id string) bool {
	if client.Closed() {
		return false
	}
	if !atomic.CompareAndSwapInt32(&client.connState,
		connStateInit, connStateConnecting) &&
		!atomic.CompareAndSwapInt32(&client.connState,
			connStateDisconnected, connStateConnecting) {
		return false
	}
	connID := "irc/" + service.MakeID("")
	client.mx.Lock()
	client.connID = connID
	client.nick = "" // Don't have a nick yet; leave blank so that nextNick() works.
	client.mx.Unlock()
	atomic.StoreInt32(&client.inick, 0) // Back at trying the first nick.

	{
		// Publish msg about the pending connection,
		// and allow it to tie the caller's ID to the new connID.
		msg := &stdchat.ConnMsg{}
		msg.Init(service.MakeID(id), "conn-state", Protocol,
			client.NetworkID(), connID, stdchat.Connecting)
		msg.Cause = "login"
		client.tp.Publish("", "", "conn", msg)
	}

	for j := 0; j < 3; j++ {
		for _, addr := range client.addrs {
			select {
			case <-ctx.Done():
				return false
			case <-client.done:
				return false
			default:
			}

			serverName, serverPort, join, wantTLS, err := parseAddr(addr)
			if err != nil {
				{
					msg := &stdchat.ConnMsg{}
					msg.Init(service.MakeID(id), "conn-state", Protocol,
						client.NetworkID(), connID, stdchat.ConnectFailed)
					msg.Cause = "parse address" // ???
					msg.Message.SetText("Error: " + err.Error())
					client.tp.Publish("", "", "conn", msg)
				}
				continue
			}
			endpoint := serverName + ":" + serverPort
			useTLS := wantTLS && client.forceTLS != -1 || client.forceTLS == 1
			dialer := &net.Dialer{Timeout: time.Minute}
			var conn net.Conn
			if useTLS {
				// TODO: DialContextWithDialer ...
				// Not merged: https://go-review.googlesource.com/c/go/+/93255/
				conn, err = tls.DialWithDialer(dialer, "tcp", endpoint, client.tlsConfig)
			} else {
				conn, err = dialer.DialContext(ctx, "tcp", endpoint)
			}
			if err != nil {
				{
					msg := &stdchat.ConnMsg{}
					msg.Init(service.MakeID(id), "conn-state", Protocol,
						client.NetworkID(), connID, stdchat.ConnectFailed)
					msg.Cause = "connection setup" // ???
					msg.Message.SetText("Error: " + err.Error())
					client.tp.Publish("", "", "conn", msg)
				}
				time.Sleep(15 * time.Second)
				continue
			}

			disconn := make(chan struct{})
			client.disconnA.Store(disconn)

			now := time.Now()
			client.mx.Lock()
			client.conn = conn
			client.lastRecvTime = now
			client.mx.Unlock()

			atomic.StoreInt32(&client.connState, connStateConnected)
			{
				msg := &stdchat.ConnMsg{}
				msg.Init(service.MakeID(id), "conn-state", Protocol,
					client.NetworkID(), connID, stdchat.Connected)
				msg.Cause = "connect" // ???
				client.tp.Publish("", "", "conn", msg)
			}

			client.recvLoopCh <- cconn{conn, disconn}
			client.sendLoopCh <- cconn{conn, disconn}

			// TODO: CAP negotiation...

			if client.pass != "" {
				client.sendLine <- "PASS " + client.pass
			}
			client.sendLine <- fmt.Sprintf("USER %s 0 %s :%s",
				client.user, serverName, client.realName)
			client.setNick(client.nicks[0])

			{
				// TODO: move this to before the first received line??
				msg := &stdchat.NetMsg{}
				msg.Init(service.MakeID(id), "online", Protocol,
					client.NetworkID())
				client.tp.Publish(msg.Network.ID, "", "network", msg)
			}

			if join != "" {
				go func() {
					for !client.Ready() {
						select {
						case <-client.done:
							return
						default:
						}
						if connID != client.ConnID() {
							return // Already reconnecting elsewhere, give up.
						}
						time.Sleep(100 * time.Millisecond)
					}
					if connID == client.ConnID() { // Only if on same connection.
						client.Join(join)
					}
				}()
			}
			return true
		}
	}

	{
		msg := &stdchat.ConnMsg{}
		msg.Init(service.MakeID(id), "conn-state", Protocol,
			client.NetworkID(), connID, stdchat.Disconnected)
		msg.Cause = "login"
		msg.Message.SetText("Unable to connect")
		client.tp.Publish("", "", "conn", msg)
	}
	atomic.StoreInt32(&client.connState, connStateDisconnected)
	return false
}

// reconnect keeps trying to connect because it implies it was connected before.
func (client *Client) reconnect(ctx context.Context, id string) bool {
	for {
		if client.connect(ctx, id) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-client.done:
			return false
		case <-time.After(time.Minute):
			continue
		}
	}
}

// https://github.com/myano/jenni/wiki/IRC-String-Formatting
var regexpCodes = regexp.MustCompile(`[\x02\x1D\x1F\x0F\x16]|\x03(\d\d?(,\d\d?)?)?`)

// stripCodes strips IRC color and other formatting codes from the string.
func stripCodes(s string) string {
	return regexpCodes.ReplaceAllLiteralString(s, "")
}

func earg(e *irc.Message, n int) string {
	if n >= len(e.Params) {
		return ""
	}
	return e.Params[n]
}

func setMessage(msg *stdchat.MessageInfo, ircMsg string) {
	if ircMsg != "" {
		textMsg := stripCodes(ircMsg)
		msg.SetText(textMsg)
		if ircMsg != textMsg {
			msg.Set("text/x-irc", ircMsg)
		}
	}
}

func (client *Client) setFrom(msg *stdchat.ChatMsg, e *irc.Message) {
	fromType := ""
	fromOrig := e.Prefix.String()
	fromName := e.Name
	fromID := fromName
	if fromOrig != "" {
		if fromOrig != fromName {
			msg.Values.Set("irc.from.who", fromOrig)
		}
		if strings.ContainsRune(fromOrig, '!') || !strings.ContainsRune(fromName, '.') {
			fromType = "user"
		} else {
			fromType = "service"
		}
		fromID = client.StringToLower(fromName)
		msg.From.Init(fromID, fromType)
		msg.From.SetName(fromName, fromName)
	}
}

func (client *Client) initChatMsg(msg *stdchat.ChatMsg, e *irc.Message, msgType string, dest string) {
	msgID, _ := e.Tags.GetTag("msgid")
	if msgID == "" {
		msgID = service.MakeID("")
	}
	msg.Init(msgID, msgType, Protocol, client.NetworkID())
	msg.Network.SetName(client.NetworkName(), "")
	if serverTime, _ := e.Tags.GetTag("time"); serverTime != "" {
		t, err := time.Parse(ServerTimeFormat, serverTime)
		if err == nil {
			msg.Time = t
		}
	}
	client.setFrom(msg, e)
	if dest != "" && dest != "*" {
		destName := ""
		destID := ""
		destType := ""
		channelName := client.chanFromTarget(dest)
		if channelName != "" {
			destName = channelName
			destType = "group"
		} else {
			// nick or server.
			if i := strings.IndexAny(dest, "!%@"); i != -1 {
				// One of the following:
				// 	nick!user@host
				// 	nick@server
				// 	nick%host
				// 	nick%host@server
				destName = dest[:i]
				destType = "private"
			} else if strings.ContainsRune(dest, '.') {
				destName = dest
				destType = "service"
			} else {
				destName = dest
				destType = "private"
			}
		}
		if dest == client.Nick() {
			// Private message to me;
			// change dest to be the other user!
			destName = msg.From.GetName()
		}
		destID = client.StringToLower(destName)
		msg.Destination.Init(destID, destType)
		msg.Destination.SetName(destName, destName)
	}
	msg.ReplyToID, _ = e.Tags.GetTag("+draft/reply") // Trust the user?
	for tname, tvalue := range e.Tags {
		switch tname {
		case "":
		case "msgid":
		case "time":
		case "+draft/reply":
			// Don't set these.
		default:
			msg.Values.Set("irc.tag."+tname, string(tvalue))
		}
	}
}

func (client *Client) newChatMsg(e *irc.Message, msgType string, dest string) *stdchat.ChatMsg {
	msg := &stdchat.ChatMsg{}
	client.initChatMsg(msg, e, msgType, dest)
	return msg
}

func (client *Client) publishOther(e *irc.Message, msgType, dest string) {
	msg := client.newChatMsg(e, msgType, dest)
	setMessage(&msg.Message, e.Trailing())
	msg.Values.Set("irc.raw", e.String())
	client.tp.Publish(client.NetworkID(), "", "other", msg)
}

func (client *Client) setChat(msg *stdchat.ChatMsg, ircMsg string) {
	if msg.Destination.ID == "" {
		// In most cases * means no value, but chats need a destination.
		msg.Destination.ID = "*"
		msg.Destination.Type = "service"
	}
	setMessage(&msg.Message, ircMsg)
}

// publishChat is newChatMsg+setChat+Publish
func (client *Client) publishChat(e *irc.Message, msgType, publishNode string) {
	msg := client.newChatMsg(e, msgType, earg(e, 0))
	client.setChat(msg, e.Trailing())
	client.tp.Publish(client.NetworkID(), msg.Destination.ID, publishNode, msg)
}

func (client *Client) doSupport(supports []string) {
	// https://modern.ircdocs.horse/#rplisupport-005
	// http://www.irc.org/tech_docs/005.html
	client.mx.Lock()
	defer client.mx.Unlock()
	support := client.support
	for _, x := range supports {
		if len(x) > 0 {
			ch := x[0]
			if ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' {
				// PARAMETER, PARAMETER=VALUE or -PARAMETER
				ix := strings.IndexFunc(x, func(r rune) bool {
					return r == '=' || r == ' '
				})
				if ix == -1 || x[ix] == '=' {
					var name, value string
					if ix == -1 {
						name = x
						value = ""
					} else {
						name = x[:ix]
						value = x[ix+1:]
					}
					if len(name) > 0 {
						if name[0] == '-' {
							name = name[1:]
							// Revert to default.
							defValue, def := defaultSupport[name]
							value = defValue
							if def {
								support[name] = value
							} else {
								delete(support, name)
							}
						} else {
							support[name] = value
						}
						client.changedSupportUnlocked(name)
					}
				}
			}
		}
	}
}

func (client *Client) setSupport(values *stdchat.ValuesInfo) {
	client.mx.RLock()
	defer client.mx.RUnlock()
	for key, value := range client.support {
		values.Set("irc.support."+key, value)
	}
}

func (client *Client) setFeatures(values *stdchat.ValuesInfo) {
	// Add various network-specific values:
	values.Set("msg-multiline", "0")
	values.Set("msg-max-length", "350") // Leave room for the entire command.
	values.Add("msg-type", "text/x-irc")
	values.Add("msg-type", "text/plain")
	client.setSupport(values)
	// TODO: msg.Values set the CAPs enabled...
}

func newTickerFunc(d time.Duration, f func()) (done chan struct{}) {
	done = make(chan struct{})
	go func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f()
			case <-done:
				return
			}
		}
	}()
	return done
}

// called by ticker
func (client *Client) tryRestoreNick() {
	// Try to get our primary nick back.
	// But don't fill up send queue with NICKs!
	// Let's only bother if there aren't many lines in queue.
	if len(client.sendLine) <= cap(client.sendLine)/4 {
		client.setNick(client.nicks[0])
	}
}

func (client *Client) nextNick() {
	inick := atomic.AddInt32(&client.inick, 1)
	tryNick := ""
	if int(inick) < len(client.nicks) {
		tryNick = client.nicks[inick]
	} else {
		tryNick = fmt.Sprintf("%s%d",
			client.nicks[int(inick)%len(client.nicks)],
			int(inick)/len(client.nicks)+1)
	}
	client.setNick(tryNick)

	client.mx.Lock()
	defer client.mx.Unlock()
	if client.fixNick == nil {
		// Setup ticker to try to get nicks[0] back!
		client.fixNick = newTickerFunc(30*time.Second, client.tryRestoreNick)
	}
}

func (client *Client) myNickChanged(newNick string) {
	client.mx.Lock()
	defer client.mx.Unlock()
	client.nick = newNick
	if client.fixNick != nil {
		// Disable the nick fix ticker if we have nick[0] or custom SetNick
		if atomic.LoadInt32(&client.inick) <= 0 {
			close(client.fixNick)
			client.fixNick = nil
		}
	}
}

func (client *Client) isFromMyself(e *irc.Message) bool {
	return e.Name == client.Nick()
}

// GetChannel gets a channel this user is on, or nil if not.
func (client *Client) GetChannel(name string) *Channel {
	client.mx.RLock()
	defer client.mx.RUnlock()
	id := client.strToLower(name)
	for _, c := range client.channels {
		if client.strToLower(c.name) == id {
			return c
		}
	}
	return nil
}

func (client *Client) GetChannels() []*Channel {
	client.mx.RLock()
	defer client.mx.RUnlock()
	return append([]*Channel(nil), client.channels...)
}

func (client *Client) removeChannel(channel *Channel) bool {
	client.mx.Lock()
	defer client.mx.Unlock()
	for i, c := range client.channels {
		if c == channel {
			ilast := len(client.channels) - 1
			client.channels[i], client.channels[ilast] = client.channels[ilast], nil
			client.channels = client.channels[:ilast]
			return true
		}
	}
	return false
}

func (client *Client) doNamesReply(channelName, strNames string) {
	channel := client.GetChannel(channelName)
	if channel == nil {
		return
	}
	names := strings.Split(strNames, " ")
	for _, name := range names {
		xnick := client.removeNickPrefixes(name)
		prefixes := name[:len(name)-len(xnick)]
		// Due to multi-prefix CAP, prefixes may be more than one prefix char.
		// https://ircv3.net/specs/extensions/multi-prefix-3.1.html
		if xnick != "" {
			// Supports userhost-in-names
			// https://ircv3.net/specs/extensions/userhost-in-names-3.2.html
			member := Member{}
			member.Prefixes = prefixes
			ibang := strings.IndexByte(xnick, '!')
			if ibang != -1 {
				member.Who = xnick
				xnick = xnick[:ibang]
			}
			member.Nick = xnick
			channel.addMember(member)
		}
	}
}

func (client *Client) publishSubscribe(channel *Channel) {
	msg := &stdchat.SubscribeMsg{}
	msg.Init(service.MakeID(""), "subscribe/irc.JOIN", Protocol, client.NetworkID())
	msg.Network.Name = client.NetworkName()
	channel.msgDest(&msg.Destination)
	channel.msgTopic(&msg.Subject)
	msg.Myself.Init(client.StringToLower(client.Nick()), "user")
	msg.Myself.SetName(client.Nick(), "")
	msg.Members = channel.GetMembersInfo()
	client.tp.Publish(msg.Network.ID, msg.Destination.ID, "subscribe", msg)
}

// ekick is nil if not a kick.
func (client *Client) publishUnsubscribe(channel *Channel, msgType string, m stdchat.MessageInfo, ekick *irc.Message) {
	msg := &stdchat.SubscribeMsg{}
	msg.Init(service.MakeID(""), msgType, Protocol, client.NetworkID())
	msg.Network.Name = client.NetworkName()
	channel.msgDest(&msg.Destination)
	//channel.msgTopic(&msg.Subject)
	msg.Myself.Init(client.StringToLower(client.Nick()), "user")
	msg.Myself.SetName(client.Nick(), "")
	msg.Message = m
	if ekick != nil {
		client.setFrom(&msg.ChatMsg, ekick)
	}
	client.tp.Publish(msg.Network.ID, msg.Destination.ID, "subscribe", msg)
}

func parseCTCP(m string) (string, string, string, bool) {
	if len(m) > 0 && m[0] == 1 {
		m = m[1:]
		if len(m) > 0 && m[len(m)-1] == 1 {
			m = m[:len(m)-1]
		}
		ctcp := m
		cargs := ""
		ispace := strings.IndexByte(m, ' ')
		if ispace != -1 {
			ctcp = m[:ispace]
			cargs = m[ispace+1:]
		}
		ctcp = strings.ToUpper(ctcp)
		return ctcp, cargs, m, true
	}
	return "", "", "", false
}

// Not myself!
func (client *Client) otherUserQuit(e *irc.Message) {
	list := make([]*Channel, 0, 2)
	func() {
		client.mx.Lock()
		defer client.mx.Unlock()
		nick := e.Name
		memberID := client.strToLower(nick)
		for _, channel := range client.channels {
			imember := channel.isOnIDUnlocked(memberID)
			if imember != -1 {
				channel.removeMemberUnlocked(imember)
			}
			list = append(list, channel)
		}
	}()
	if len(list) != 0 { // Publish group-leave. Outside of above lock!
		var m stdchat.MessageInfo
		setMessage(&m, e.Trailing())
		for _, channel := range list {
			msg := &stdchat.LeaveMsg{}
			client.initChatMsg(&msg.ChatMsg, e, "group-leave/irc.QUIT", channel.name)
			msg.User = msg.From
			msg.From = stdchat.EntityInfo{}
			msg.Message = m
			client.tp.Publish(msg.Network.ID, msg.Destination.ID, "group", msg)
		}
	}
}

func (client *Client) memberChangedNick(oldNick, newNick string) {
	type t struct {
		channel *Channel
		member  Member
	}
	list := make([]t, 0, 2)
	oldMemberID := client.StringToLower(oldNick)
	func() {
		client.mx.Lock()
		defer client.mx.Unlock()
		for _, channel := range client.channels {
			imember := channel.isOnIDUnlocked(oldMemberID)
			if imember != -1 {
				member := channel.members[imember]
				member.Nick = newNick
				ibang := strings.IndexByte(member.Who, '!')
				if ibang != -1 {
					member.Who = newNick + member.Who[ibang:]
				}
				channel.members[imember] = member
				list = append(list, t{channel, member})
			}
		}
	}()
	if len(list) != 0 { // Publish member-changed. Outside of above lock!
		for _, x := range list {
			msg := &stdchat.MemberChangedMsg{}
			msg.Init(service.MakeID(""), "member-changed/irc.NICK",
				Protocol, client.NetworkID())
			msg.Network.Name = client.NetworkName()
			msg.User.Init(oldMemberID, "user")
			msg.User.SetName(oldNick, "")
			msg.Member = x.member.GetMemberInfo(x.channel)
			client.tp.Publish(msg.Network.ID, msg.Destination.ID, "group", msg)
		}
	}
}

func (client *Client) modesChanged(e *irc.Message) {
	target := earg(e, 0)
	msg := client.newChatMsg(e, "other/irc.MODE", target)
	if len(e.Params) > 1 {
		setMessage(&msg.Message, strings.Join(e.Params[1:], " "))
	}
	channelName := client.chanFromTarget(target)
	isChan := channelName != ""
	type t struct {
		nick   string
		mode   byte
		prefix byte
		member Member // set later, after updating prefixes
	}
	var prefixesChanged []t // isChan only
	plus := true
	modes := earg(e, 1)
	imodeparam := 2
	for i := 0; i < len(modes); i++ {
		mode := modes[i]
		if mode == '+' {
			plus = true
		} else if mode == '-' {
			plus = false
		} else {
			hasArg := isChan && client.chanModeType(mode).HasArg(plus)
			argValue := "-"
			if plus {
				argValue = "+"
			}
			argValue += modes[i : i+1]
			if hasArg && imodeparam < len(e.Params) {
				modeArg := e.Params[imodeparam]
				argValue += " " + modeArg
				imodeparam++
				if isChan {
					prefix := client.GetNickPrefix(mode)
					if prefix != 0 {
						prefixesChanged = append(prefixesChanged,
							t{modeArg, mode, prefix, Member{}})
					}
				}
			}
			if isChan {
				msg.Values.Add("irc.channel-mode-changed."+modes[i:i+1], argValue)
			} else {
				msg.Values.Add("irc.user-mode-changed."+modes[i:i+1], argValue)
			}
		}
	}
	client.tp.Publish(msg.Network.ID, msg.Destination.ID, "other", msg)
	if len(prefixesChanged) != 0 {
		channel := client.GetChannel(channelName)
		if channel != nil {
			_, allPrefixes := client.GetPrefix()
			// Update prefixes:
			func() {
				client.mx.Lock()
				defer client.mx.Unlock()
				for ichanged, x := range prefixesChanged {
					memberID := client.strToLower(x.nick)
					imember := channel.isOnIDUnlocked(memberID)
					if imember != -1 {
						member := channel.members[imember]
						oldPrefixes := member.Prefixes
						member.Prefixes = insertPrefix(oldPrefixes, x.prefix, allPrefixes)
						if member.Prefixes != oldPrefixes { // If prefix change...
							channel.members[imember] = member         // Update.
							prefixesChanged[ichanged].member = member // set member
						}
					}
				}
			}()
			// Publish member-changed:
			for _, x := range prefixesChanged {
				if x.member.Nick != "" { // member is empty if no prefix change.
					// TODO: handle the case when the same user gets multiple prefixes at once.
					// e.g. handle +ov user user in one msg.
					// For now, handling them separately.
					mcmsg := &stdchat.MemberChangedMsg{}
					mcmsg.Init(service.MakeID(""), "member-changed", Protocol, msg.Network.ID)
					mcmsg.Network = msg.Network
					mcmsg.Destination = msg.Destination
					mcmsg.From = msg.Destination
					mcmsg.Member = x.member.GetMemberInfo(channel)
					mcmsg.User.Init(mcmsg.Member.Info.User.ID, "user")
					mcmsg.User.Name = mcmsg.Member.Info.User.Name // Not the same display name.
					client.tp.Publish(mcmsg.Network.ID, mcmsg.Destination.ID, "group", mcmsg)
				}
			}
		}
	}
}

func (client *Client) ircEvent(e *irc.Message) {
	now := time.Now()
	client.mx.Lock()
	client.lastRecvTime = now
	client.mx.Unlock()

	if client.Verbose {
		log.Printf("<- %s", e.String())
	}

	switch e.Command {
	case RPL_WELCOME:
		newNick := earg(e, 0)
		client.myNickChanged(newNick)

		func() {
			// Reset stuff in lock.
			client.mx.Lock()
			defer client.mx.Unlock()

			client.support = defaultSupport.clone()
			client.changedAllSupportUnlocked()

			// Auto rejoin channels.
			// TODO: what if they haven't auth'd yet??
			for _, channel := range client.channels {
				// TODO: handle if channel has a key.
				client.Join(channel.name)
			}
		}()

		{
			msg := &stdchat.UserChangedMsg{}
			msg.Init(service.MakeID(""), "user-changed", Protocol, client.NetworkID())
			msg.User.Init(client.StringToLower(newNick), "user")
			msg.User.SetName(newNick, newNick)
			msg.Info.User = msg.User
			msg.Myself = true
			client.tp.Publish(msg.Network.ID, "", "user", msg)
		}
		client.publishOther(e, "other/irc."+e.Command, "")

	case RPL_ISUPPORT:
		client.doSupport(e.Params[1:])
		client.publishOther(e, "other/irc."+e.Command, "")

	case ERR_NOMOTD, RPL_ENDOFMOTD:
		atomic.CompareAndSwapInt32(&client.state, stateStarted, stateReady)
		client.publishOther(e, "other/irc."+e.Command, "")
		{
			msg := &stdchat.NetMsg{}
			msg.Init(service.MakeID(""), "ready", Protocol, client.NetworkID())
			msg.Network.SetName(client.NetworkName(), "")
			client.setFeatures(&msg.Values)
			client.tp.Publish(msg.Network.ID, "", "network", msg)
		}

	case "NICK":
		newNick := earg(e, 0)
		myself := false
		if client.isFromMyself(e) {
			client.myNickChanged(newNick)
			myself = true
		}
		{
			msg := &stdchat.UserChangedMsg{}
			client.initChatMsg(&msg.ChatMsg, e, "user-changed/irc."+e.Command, "")
			msg.User = msg.From
			msg.Info.User.Init(client.StringToLower(newNick), "user")
			msg.Myself = myself
			client.tp.Publish(msg.Network.ID, "", "user", msg)
		}
		client.memberChangedNick(e.Name, newNick)

	case ERR_NICKNAMEINUSE, ERR_UNAVAILRESOURCE, ERR_NICKCOLLISION:
		client.publishOther(e, "other/irc."+e.Command, "")
		if client.Nick() == "" {
			client.nextNick()
		}

	case ERR_ERRONEUSNICKNAME, ERR_NONICKNAMEGIVEN:
		client.publishOther(e, "other/irc."+e.Command, "")
		if client.Nick() == "" {
			// They don't have a nick and the one we tried is invalid,
			// so set one known to be good, within 9 chars.
			client.SetNick(fmt.Sprintf("Guest%d", rand.Intn(10000)))
		}

	case "PRIVMSG":
		node := "msg"
		if client.isFromMyself(e) {
			node += "-out"
		}
		if ctcp, cargs, m, ok := parseCTCP(e.Trailing()); ok {
			if ctcp == "ACTION" {
				// Special handling of ACTION /me
				msg := client.newChatMsg(e, "msg/action/irc.PRIVMSG.CTCP.ACTION", earg(e, 0))
				client.setChat(msg, cargs)
				client.tp.Publish(client.NetworkID(), msg.Destination.ID, node, msg)
			} else {
				node = "other"
				if client.isFromMyself(e) {
					node += "-out"
				}
				switch ctcp {
				case "VERSION":
					client.SendCTCPReply(e.Name, "VERSION", client.version)
				case "PING":
					client.SendCTCPReply(e.Name, "PING", cargs)
				}
				msgType := "other/irc.PRIVMSG.CTCP." + ctcp
				msg := client.newChatMsg(e, msgType, earg(e, 0))
				msg.Values.Set("irc.CTCP", m)
				client.tp.Publish(client.NetworkID(), msg.Destination.ID, node, msg)
			}
		} else {
			client.publishChat(e, "msg/irc.PRIVMSG", node)
		}

	case "NOTICE":
		if ctcp, _, m, ok := parseCTCP(e.Trailing()); ok {
			node := "other"
			if client.isFromMyself(e) {
				node += "-out"
			}
			msgType := "other/irc.NOTICE.CTCPREPLY." + ctcp
			msg := client.newChatMsg(e, msgType, earg(e, 0))
			msg.Values.Set("irc.CTCPREPLY", m)
			client.tp.Publish(client.NetworkID(), msg.Destination.ID, node, msg)
		} else {
			node := "info"
			if client.isFromMyself(e) {
				node += "-out"
			}
			client.publishChat(e, "info/irc.NOTICE", node)
		}

	case "TAGMSG": // PRIVMSG without a message; just tags.
		msg := client.newChatMsg(e, "other/irc.TAGMSG", earg(e, 0))
		client.setChat(msg, "")
		client.tp.Publish(client.NetworkID(), msg.Destination.ID, "other", msg)

	case "JOIN":
		channelName := earg(e, 0)
		if client.isFromMyself(e) {
			if client.GetChannel(channelName) == nil {
				func() {
					channel := &Channel{
						client: client,
						name:   channelName,
					}
					client.mx.Lock()
					defer client.mx.Unlock()
					client.channels = append(client.channels, channel)
				}()
			}
			// Since subscription is being delayed to merge multiple values,
			// we'll send this out as a regular other message.
			client.publishOther(e, "other/irc.JOIN", "")
		} else {
			channel := client.GetChannel(channelName)
			if channel != nil {
				// TODO: handle extended-join...
				channel.addMember(Member{Nick: e.Name})
				{
					msg := &stdchat.EnterMsg{}
					client.initChatMsg(&msg.ChatMsg, e, "group-enter/irc.JOIN", channelName)
					msg.Member.Type = "member"
					msg.Member.Info.User = msg.From
					msg.From = stdchat.EntityInfo{}
					client.tp.Publish(msg.Network.ID, msg.Destination.ID, "group", msg)
				}
			}
		}

	case RPL_NOTOPIC:
		client.publishOther(e, "other/irc."+e.Command, "")
		channelName := earg(e, 1)
		channel := client.GetChannel(channelName)
		if channel != nil {
			channel.clearTopic()
		}

	case RPL_TOPIC:
		client.publishOther(e, "other/irc."+e.Command, "")
		channelName := earg(e, 1)
		channel := client.GetChannel(channelName)
		if channel != nil {
			channel.setTopicFromEvent(e)
		}

	case RPL_NAMREPLY:
		client.publishOther(e, "other/irc."+e.Command, "")
		if len(e.Params) >= 4 {
			channelName := earg(e, 2)
			strNames := e.Trailing()
			client.doNamesReply(channelName, strNames)
		}

	case RPL_ENDOFNAMES:
		client.publishOther(e, "other/irc."+e.Command, "")
		channelName := earg(e, 1)
		channel := client.GetChannel(channelName)
		if channel != nil {
			channel.addFlags(chanFlagGotMembers)
			if channel.needPublishSubscribe() {
				client.publishSubscribe(channel)
			}
		}

	case "QUIT":
		if client.isFromMyself(e) {
			m := stdchat.MessageInfo{}
			setMessage(&m, e.Trailing())
			client.maybeUnsubscribeAll("unsubscribe/irc.QUIT", m)
			client.disconnect("quit")
			// Note: not clearing the channels here,
			// so that we can re-join them on reconnect!
		} else {
			client.otherUserQuit(e)
		}

	//case "KILL": // TODO: ...

	//case "ERROR": // TODO: ...

	case "PART":
		channelName := earg(e, 0)
		if client.isFromMyself(e) {
			channel := client.GetChannel(channelName)
			if channel != nil {
				client.removeChannel(channel)
				m := stdchat.MessageInfo{}
				setMessage(&m, e.Trailing())
				client.publishUnsubscribe(channel, "unsubscribe/irc.PART", m, nil)
			}
		} else {
			channel := client.GetChannel(channelName)
			if channel != nil {
				channel.removeMember(e.Name)
				{
					msg := &stdchat.LeaveMsg{}
					client.initChatMsg(&msg.ChatMsg, e, "group-leave/irc.PART", channelName)
					msg.User = msg.From
					msg.From = stdchat.EntityInfo{}
					setMessage(&msg.Message, e.Trailing())
					client.tp.Publish(msg.Network.ID, msg.Destination.ID, "group", msg)
				}
			}
		}

	case "KICK":
		channelName := earg(e, 0)
		kickedNick := earg(e, 1)
		kickedNickID := client.StringToLower(kickedNick)
		if kickedNickID == client.NickID() { // I was kicked.
			channel := client.GetChannel(channelName)
			if channel != nil {
				client.removeChannel(channel)
				{
					m := stdchat.MessageInfo{}
					setMessage(&m, e.Trailing())
					client.publishUnsubscribe(channel, "unsubscribe/irc.KICK", m, e)
				}
			}
		} else {
			channel := client.GetChannel(channelName)
			if channel != nil {
				channel.removeMember(kickedNick)
				{
					msg := &stdchat.LeaveMsg{}
					client.initChatMsg(&msg.ChatMsg, e, "group-leave/irc.KICK", channelName)
					msg.User.Init(kickedNickID, "user")
					msg.User.SetName(kickedNick, "")
					setMessage(&msg.Message, e.Trailing())
					client.tp.Publish(msg.Network.ID, msg.Destination.ID, "group", msg)
				}
			}
		}

	case "MODE":
		client.modesChanged(e)

	case "PING":
		client.TrySendLine("PONG :" + e.Trailing())
	case "PONG":
		// Don't publish ping/pong from server, it's noise.

	default:
		client.publishOther(e, "other/irc."+e.Command, "")
	}
}

var cleanReplacer = strings.NewReplacer(
	"\r", "",
	"\n", " ",
)

func cleanMsg(s string) string {
	return cleanReplacer.Replace(s)
}

func ircMsgInfo(msg *stdchat.ChatMsg) (dest, ircMsg string, err error) {
	dest = msg.Destination.ID
	if dest == "" {
		err = errors.New("no destination specified")
		return
	}
	if strings.IndexAny(dest, " \t\r\n,") != -1 {
		err = errors.New("invalid destination")
		return
	}
	ircMsg = msg.Message.Get("text/x-irc").Content
	if ircMsg == "" {
		ircMsg = msg.Message.String()
		if ircMsg == "" {
			for _, m := range msg.Message {
				if strings.HasPrefix(m.Type, "text/") {
					ircMsg = fmt.Sprintf("[%s] %s", m.Type, m.Content)
					break
				} else if ircMsg == "" {
					ircMsg = fmt.Sprintf("[%s]", m.Type)
				}
			}
			if ircMsg == "" {
				err = errors.New("no message content specified")
				return
			}
		}
	}
	/*if strings.IndexAny(ircMsg, "\r\n") != -1 {
		err = errors.New("invalid message content")
		return
	}*/
	ircMsg = cleanMsg(ircMsg)
	return
}

func (client *Client) Handler(msg *stdchat.ChatMsg) {
	/* // Not doing this, don't modify caller's msg...
	if msg.Network.ID == "" {
		msg.Network.Init(client.NetworkID(), "net")
		msg.Network.SetName(client.NetworkName(), "")
	}
	msg.Protocol = Protocol
	*/
	if msg.Network.ID == "" {
		panic("network ID")
	}

	switch msg.Type {
	case "msg", "msg/irc.PRIVMSG":
		dest, ircMsg, err := ircMsgInfo(msg)
		if err != nil {
			client.tp.PublishError(service.MakeID(msg.ID), msg.Network.ID, err)
		} else {
			client.SendMsg(dest, ircMsg)
		}
	case "msg/action", "msg/action/irc.PRIVMSG.CTCP.ACTION":
		dest, ircMsg, err := ircMsgInfo(msg)
		if err != nil {
			client.tp.PublishError(service.MakeID(msg.ID), msg.Network.ID, err)
		} else {
			client.SendAction(dest, ircMsg)
		}
	case "info", "info/irc.NOTICE":
		dest, ircMsg, err := ircMsgInfo(msg)
		if err != nil {
			client.tp.PublishError(service.MakeID(msg.ID), msg.Network.ID, err)
		} else {
			client.SendNotice(dest, ircMsg)
		}
	default:
		client.tp.PublishError(service.MakeID(msg.ID), msg.Network.ID,
			errors.New("unhandled message of type "+msg.Type))
	}
}

func (client *Client) CmdHandler(msg *stdchat.CmdMsg) {
	switch msg.Command {
	case "raw":
		if client.svc.CheckArgs(1, msg) {
			if len(msg.Args) == 1 && msg.Args[0] != "" {
				client.SendLine(msg.Args[0])
			} else {
				client.tp.PublishError(msg.ID, msg.Network.ID,
					errors.New("invalid raw cmd for "+Protocol))
			}
		}
	default:
		client.tp.PublishError(msg.ID, msg.Network.ID,
			errors.New("unhandled command: "+msg.Command))
	}
}
