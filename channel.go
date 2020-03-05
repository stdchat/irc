// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package irc

import (
	"strings"
	"sync/atomic"

	"github.com/go-irc/irc"
	"stdchat.org"
)

type chanFlags uint32

const (
	chanFlagNone       chanFlags = 0
	chanFlagGotMembers chanFlags = 1 << iota // got RPL_ENDOFNAMES
	chanFlagPublishedSubscribe
)

type Channel struct {
	client  *Client
	members []Member            // locked by mx
	name    string              // locked by mx
	topic   stdchat.MessageInfo // locked by mx
	flags   uint32              // atomic
}

func (channel *Channel) getFlags() chanFlags {
	return chanFlags(atomic.LoadUint32(&channel.flags))
}

// replaces all the flags.
func (channel *Channel) setFlags(flags chanFlags) {
	atomic.StoreUint32(&channel.flags, uint32(flags))
}

// Add in the flags to the existing flags, returns the new flags.
func (channel *Channel) addFlags(flags chanFlags) chanFlags {
	for {
		oldFlags := channel.getFlags()
		newFlags := oldFlags | flags
		if atomic.CompareAndSwapUint32(&channel.flags,
			uint32(oldFlags), uint32(newFlags)) {
			return newFlags
		}
	}
}

func (channel *Channel) needPublishSubscribe() bool {
	const need = chanFlagGotMembers
	for {
		flags := channel.getFlags()
		if flags&(need|chanFlagPublishedSubscribe) != need {
			return false
		}
		if atomic.CompareAndSwapUint32(&channel.flags,
			uint32(flags), uint32(flags|chanFlagPublishedSubscribe)) {
			return true
		}
	}
}

func (channel *Channel) msgDest(dest *stdchat.EntityInfo) {
	channel.client.mx.RLock()
	defer channel.client.mx.RUnlock()
	dest.Init(channel.client.strToLower(channel.name), "group")
	dest.SetName(channel.name, "")
}

func (channel *Channel) msgTopic(msg *stdchat.MessageInfo) {
	channel.client.mx.RLock()
	defer channel.client.mx.RUnlock()
	*msg = channel.topic
}

func (channel *Channel) clearTopic() {
	channel.client.mx.Lock()
	channel.topic = stdchat.MessageInfo{}
	channel.client.mx.Unlock()
}

func (channel *Channel) setTopicFromEvent(e *irc.Message) {
	channel.client.mx.Lock()
	defer channel.client.mx.Unlock()
	setMessage(&channel.topic, e.Trailing())
}

func (channel *Channel) addMember(member Member) {
	channel.client.mx.Lock()
	defer channel.client.mx.Unlock()
	channel.members = append(channel.members, member)
}

// use isOnIDUnlocked to get index i.
func (channel *Channel) removeMemberUnlocked(i int) {
	ilast := len(channel.members) - 1
	channel.members[i], channel.members[ilast] = channel.members[ilast], Member{}
	channel.members = channel.members[:ilast]
}

func (channel *Channel) removeMember(nick string) bool {
	channel.client.mx.Lock()
	defer channel.client.mx.Unlock()
	i := channel.isOnIDUnlocked(channel.client.strToLower(nick))
	if i != -1 {
		channel.removeMemberUnlocked(i)
		return true
	}
	return false
}

// Returns index in members, or -1
func (channel *Channel) isOnIDUnlocked(memberID string) int {
	for i, member := range channel.members {
		if channel.client.strToLower(member.Nick) == memberID {
			return i
		}
	}
	return -1
}

// Member.Valid() is false if nick is not on this channel.
func (channel *Channel) IsOn(nick string) Member {
	channel.client.mx.RLock()
	defer channel.client.mx.RUnlock()
	i := channel.isOnIDUnlocked(channel.client.strToLower(nick))
	if i == -1 {
		return Member{}
	}
	return channel.members[i]
}

func (channel *Channel) getMembersInfoUnlocked() []stdchat.MemberInfo {
	members := make([]stdchat.MemberInfo, len(channel.members))
	for i, member := range channel.members {
		members[i] = member.getMemberInfoUnlocked(channel)
	}
	return members
}

func (channel *Channel) GetMembersInfo() []stdchat.MemberInfo {
	channel.client.mx.RLock()
	defer channel.client.mx.RUnlock()
	return channel.getMembersInfoUnlocked()
}

func (channel *Channel) getStateInfoUnlocked(net stdchat.EntityInfo) stdchat.SubscriptionStateInfo {
	msg := stdchat.SubscriptionStateInfo{}
	msg.Type = "subscription-state"
	msg.Network = net
	msg.Protocol = Protocol
	msg.Destination.Init(channel.client.strToLower(channel.name), "group")
	msg.Destination.SetName(channel.name, "")
	msg.Subject = channel.topic
	msg.Members = channel.getMembersInfoUnlocked()
	return msg
}

func (channel *Channel) GetStateInfo() stdchat.SubscriptionStateInfo {
	net := stdchat.EntityInfo{}
	net.Init(channel.client.NetworkID(), "net")
	net.SetName(channel.client.NetworkName(), "")
	channel.client.mx.RLock()
	defer channel.client.mx.RUnlock()
	return channel.getStateInfoUnlocked(net)
}

type Member struct {
	Prefixes string
	Nick     string
	Who      string // nick!user@host if known, empty otherwise.
}

func (member Member) Valid() bool {
	return member.Nick != ""
}

func (member Member) getMemberInfoUnlocked(channel *Channel) stdchat.MemberInfo {
	m := stdchat.MemberInfo{}
	m.Type = "member"
	m.Info.User.Init(channel.client.strToLower(member.Nick), "user")
	dispName := ""
	if member.Prefixes != "" {
		dispName = member.Prefixes[:1] + member.Nick // Use highest rank prefix.
		m.Values.Set("irc.prefix", member.Prefixes)
	}
	if member.Who != "" {
		m.Values.Set("irc.who", member.Who)
	}
	m.Info.User.SetName(member.Nick, dispName)
	return m
}

func (member Member) GetMemberInfo(channel *Channel) stdchat.MemberInfo {
	channel.client.mx.Lock()
	defer channel.client.mx.Unlock()
	return member.getMemberInfoUnlocked(channel)
}

func insertPrefix(toPrefixes string, prefix byte, allPrefixesOrder string) string {
	prefixOrd := strings.IndexByte(allPrefixesOrder, prefix)
	if prefixOrd == -1 {
		return toPrefixes // Not a prefix.
	}
	for i := 0; i < len(toPrefixes); i++ {
		pOrd := strings.IndexByte(allPrefixesOrder, toPrefixes[i])
		if pOrd > prefixOrd {
			return toPrefixes[:i] + string(prefix) + toPrefixes[i:]
		}
		if prefixOrd == pOrd {
			return toPrefixes // Already there.
		}
	}
	return toPrefixes + string(prefix) // Lowest.
}
