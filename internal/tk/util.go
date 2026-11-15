// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package tk

import (
	"net"

	"github.com/loxilb-io/loxilib"
)

type (
	Counter  = loxilib.Counter
	IfiStat  = loxilib.IfiStat
	TrieData = loxilib.TrieData
	TrieRoot = loxilib.TrieRoot
)

const (
	MaxSidx  = loxilib.MaxSidx
	RxBytes  = loxilib.RxBytes
	RxErrors = loxilib.RxErrors
	RxPkts   = loxilib.RxPkts
	TxBytes  = loxilib.TxBytes
	TxErrors = loxilib.TxErrors
	TxPkts   = loxilib.TxPkts
)

func ArpPing(dst, src net.IP, ifName string) (int, error) { return loxilib.ArpPing(dst, src, ifName) }
func Htonl(v uint32) uint32                               { return loxilib.Htonl(v) }
func Htons(v uint16) uint16                               { return loxilib.Htons(v) }
func IPtonl(ip net.IP) uint32                             { return loxilib.IPtonl(ip) }
func IsNetIPv4(address string) bool                       { return loxilib.IsNetIPv4(address) }
func IsNetIPv6(address string) bool                       { return loxilib.IsNetIPv6(address) }
func L4ServiceProber(kind, name, hint, request, response string) bool {
	return loxilib.L4ServiceProber(kind, name, hint, request, response)
}
func NetGetIfiStats(ifName string, stats *IfiStat) int { return loxilib.NetGetIfiStats(ifName, stats) }
func NewCounter(begin, length uint64) *Counter         { return loxilib.NewCounter(begin, length) }
func NltoIP(addr uint32) net.IP                        { return loxilib.NltoIP(addr) }
func Ntohl(v uint32) uint32                            { return loxilib.Ntohl(v) }
func Ntohs(v uint16) uint16                            { return loxilib.Ntohs(v) }
func TrieInit(v6 bool) *TrieRoot                       { return loxilib.TrieInit(v6) }
