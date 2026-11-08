/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bfd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

type SessionState uint8

const (
	BFDAdminDown SessionState = iota
	BFDDown
	BFDInit
	BFDUp
)

var BFDStateMap = map[uint8]string{
	uint8(BFDAdminDown): "BFDAdminDown",
	uint8(BFDDown):      "BFDDown",
	uint8(BFDInit):      "BFDInit",
	uint8(BFDUp):        "BFDUp",
}

const (
	BFDMinSysTXIntervalUs = 100000
	BFDDflSysTXIntervalUs = 200000
	BFDMinSysRXIntervalUs = 200000
	BFDIncrDiscVal        = 0x00000001
)

type ConfigArgs struct {
	// StartGate defers protocol traffic while keeping accepted configuration
	// visible to capture. A nil gate starts immediately.
	StartGate <-chan struct{}
	RemoteIP  string
	SourceIP  string
	Port      uint16
	Interval  uint32
	Multi     uint8
	Instance  string
}

type WireRaw struct {
	Version       uint8
	Length        uint8
	State         SessionState
	Multi         uint8
	Disc          uint32
	RDisc         uint32
	DesMinTxInt   uint32
	ReqMinRxInt   uint32
	ReqMinEchoInt uint32
}

type Notifer interface {
	BFDSessionNotify(instance string, remote string, state string)
}

type bfdSession struct {
	StartGate      <-chan struct{}
	RemoteName     string
	Instance       string
	Cxn            net.Conn
	State          SessionState
	CiState        string
	MyMulti        uint8
	RemMulti       uint8
	MyIP           net.IP
	MyDisc         uint32
	RemDisc        uint32
	DesMinTxInt    uint32
	RemDesMinTxInt uint32
	ReqMinRxInt    uint32
	TimeOut        uint32
	ReqMinEchoInt  uint32
	LastRxTS       time.Time
	TxTicker       *time.Ticker
	RxTicker       *time.Ticker
	Fin            chan bool
	Mutex          sync.RWMutex
	Notify         Notifer
	PktDat         [24]byte

	// Leases are accepted under Mutex until stopping is published. The
	// operation token serializes transitions/callbacks without holding the
	// table or state lock across an external notifier.
	stopping     bool
	started      bool
	stopOnce     sync.Once
	finalizeOnce sync.Once
	done         chan struct{}
	work         sync.WaitGroup
	ops          chan struct{}
}

type Struct struct {
	BFDSessMap map[string]*bfdSession
	BFDMtx     sync.RWMutex
}

func StructNew(port uint16) *Struct {
	bfdStruct := new(Struct)

	bfdStruct.BFDSessMap = make(map[string]*bfdSession)
	go bfdStruct.bfdStartListener(port)
	return bfdStruct
}

func (bs *Struct) BFDAddRemote(args ConfigArgs, cbs Notifer) error {
	bs.BFDMtx.Lock()
	if sess := bs.BFDSessMap[args.RemoteIP]; sess != nil {
		bs.BFDMtx.Unlock()
		return sess.update(args)
	}
	defer bs.BFDMtx.Unlock()
	if args.Interval < BFDMinSysTXIntervalUs || args.Multi == 0 {
		return errors.New("bfd malformed args")
	}
	sess := &bfdSession{Instance: args.Instance, Notify: cbs, StartGate: args.StartGate}
	if err := sess.initialize(args.RemoteIP, args.SourceIP, args.Port, args.Interval, args.Multi); err != nil {
		return err
	}
	bs.BFDSessMap[args.RemoteIP] = sess
	return nil
}

const bfdSessionStopWait = time.Second

func (b *bfdSession) beginWork() bool {
	b.Mutex.Lock()
	defer b.Mutex.Unlock()
	if b.stopping {
		return false
	}
	b.work.Add(1)
	return true
}

func (b *bfdSession) takeOperation(timeout time.Duration) error {
	if timeout == 0 {
		select {
		case b.ops <- struct{}{}:
			return nil
		case <-b.Fin:
			return errors.New("bfd session is stopping")
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b.ops <- struct{}{}:
		return nil
	case <-b.Fin:
		return errors.New("bfd session is stopping")
	case <-timer.C:
		return errors.New("bfd session update timed out")
	}
}

func (b *bfdSession) update(args ConfigArgs) error {
	if !b.beginWork() {
		return errors.New("bfd session is stopping")
	}
	defer b.work.Done()
	b.Mutex.RLock()
	source := net.ParseIP(args.SourceIP)
	valid := source != nil && (source.IsUnspecified() || b.MyIP.Equal(source)) && b.RemoteName == fmt.Sprintf("%s:%d", args.RemoteIP, args.Port) && b.Instance == args.Instance
	unchanged := (args.Interval == 0 || b.DesMinTxInt == args.Interval) && (args.Multi == 0 || b.MyMulti == args.Multi)
	b.Mutex.RUnlock()
	if !valid {
		return errors.New("bfd existing session source, port or instance differs")
	}
	if unchanged {
		return nil
	}
	if err := b.takeOperation(bfdSessionStopWait); err != nil {
		return err
	}
	defer func() { <-b.ops }()
	b.Mutex.Lock()
	defer b.Mutex.Unlock()
	if b.stopping {
		return errors.New("bfd session is stopping")
	}
	changed := false
	if args.Interval != 0 && b.DesMinTxInt != args.Interval {
		b.DesMinTxInt, b.ReqMinRxInt, b.ReqMinEchoInt = args.Interval, args.Interval, args.Interval
		changed = true
	}
	if args.Multi != 0 && b.MyMulti != args.Multi {
		b.MyMulti = args.Multi
		changed = true
	}
	if changed {
		b.State = BFDDown
		// One worker owns both stable ticker pointers for the whole session.
		b.TxTicker.Reset(time.Duration(b.DesMinTxInt) * time.Microsecond)
	}
	return nil
}

func (b *bfdSession) requestStop() {
	b.stopOnce.Do(func() {
		b.Mutex.Lock()
		b.stopping = true
		close(b.Fin)
		b.Mutex.Unlock()
		go func() { b.work.Wait(); close(b.done) }()
	})
}

func (bs *Struct) BFDDeleteRemote(args ConfigArgs) error {
	bs.BFDMtx.Lock()
	sess := bs.BFDSessMap[args.RemoteIP]
	if sess == nil {
		bs.BFDMtx.Unlock()
		return errors.New("no bfd session")
	}
	sess.requestStop() // close-only; never waits for a receiver or callback
	bs.BFDMtx.Unlock()
	if err := sess.destruct(); err != nil {
		tk.LogIt(tk.LogWarning, "remote %s: bfd session stop timed out; session retained for retry\n", args.RemoteIP)
		return err
	}
	bs.BFDMtx.Lock()
	if bs.BFDSessMap[args.RemoteIP] == sess {
		delete(bs.BFDSessMap, args.RemoteIP)
	}
	bs.BFDMtx.Unlock()
	return nil
}

func (bs *Struct) BFDGet() ([]cmn.BFDMod, error) {
	var res []cmn.BFDMod

	bs.BFDMtx.RLock()
	defer bs.BFDMtx.RUnlock()

	for _, s := range bs.BFDSessMap {
		s.Mutex.RLock()
		var temp cmn.BFDMod
		pair := strings.Split(s.RemoteName, ":")
		temp.Instance = s.Instance
		temp.RemoteIP = net.ParseIP(pair[0])
		temp.SourceIP = s.MyIP
		port, _ := strconv.Atoi(pair[1])
		temp.Port = uint16(port)
		temp.Interval = uint64(s.DesMinTxInt)
		temp.RetryCount = s.MyMulti
		temp.State = BFDStateMap[uint8(s.State)]
		s.Mutex.RUnlock()
		res = append(res, temp)
	}

	return res, nil
}

func decodeCtrlPacket(buf []byte, size int) *WireRaw {

	if size < 24 {
		return nil
	}

	var raw WireRaw

	raw.Version = buf[0] >> 5 & 0x7
	raw.State = SessionState(buf[1] >> 6 & 0x3)
	raw.Multi = buf[2]
	raw.Length = buf[3]

	raw.Disc = binary.BigEndian.Uint32(buf[4:])
	raw.RDisc = binary.BigEndian.Uint32(buf[8:])
	raw.DesMinTxInt = binary.BigEndian.Uint32(buf[12:])
	raw.ReqMinRxInt = binary.BigEndian.Uint32(buf[16:])
	raw.ReqMinEchoInt = binary.BigEndian.Uint32(buf[20:])

	return &raw
}

func (bs *Struct) processBFD(conn *net.UDPConn) {
	var buf [1024]byte

	n, addr, err := conn.ReadFromUDP(buf[:])
	if err != nil {
		return
	}

	raw := decodeCtrlPacket(buf[:], n)
	if raw == nil {
		return
	}

	remIP := addr.IP
	if remIP != nil {
		//fmt.Printf("raw %v:%s:%v\n", raw, remIP.String(), raw.State)
		bs.BFDMtx.RLock()
		sess := bs.BFDSessMap[remIP.String()]
		bs.BFDMtx.RUnlock()
		if sess != nil && sess.active() {
			sess.RunSessionSM(raw)
		} /* else {
			tk.LogIt(tk.LogDebug, "bfd session(%s) not found\n", remIP.String())
		} */
	}
}

func (bs *Struct) bfdStartListener(port uint16) error {
	localName := fmt.Sprintf("%s:%d", "0.0.0.0", port)
	addr, err := net.ResolveUDPAddr("udp4", localName)
	if err != nil {
		return errors.New("failed to resolve to BFD addr")
	}

	lc, err1 := net.ListenUDP("udp4", addr)
	if err1 != nil {
		return errors.New("failed to listen to BFD")
	}

	defer lc.Close()

	for {
		bs.processBFD(lc)
	}

}

func (b *bfdSession) RunSessionSM(raw *WireRaw) {
	if raw == nil || !b.beginWork() {
		return
	}
	defer b.work.Done()
	if err := b.takeOperation(0); err != nil {
		return
	}
	defer func() { <-b.ops }()
	b.Mutex.Lock()
	if b.stopping || !b.gateOpen() {
		b.Mutex.Unlock()
		return
	}
	b.started = true
	oldState := b.State

	b.RemMulti = raw.Multi
	b.RemDisc = raw.Disc
	b.RemDesMinTxInt = raw.DesMinTxInt
	if b.RemDesMinTxInt > b.ReqMinRxInt {
		b.TimeOut = uint32(b.RemMulti) * b.RemDesMinTxInt
	} else {
		b.TimeOut = uint32(b.RemMulti) * b.ReqMinRxInt
	}
	b.LastRxTS = time.Now()

	if raw.State == BFDDown {
		if b.State == BFDDown {
			b.State = BFDInit
			tk.LogIt(tk.LogInfo, "%s: BFD State -> INIT\n", b.RemoteName)
		}
	} else if raw.State == BFDInit {
		if b.State != BFDUp {
			b.State = BFDUp
			tk.LogIt(tk.LogInfo, "%s: BFD State -> UP\n", b.RemoteName)
		}
	} else if raw.State == BFDAdminDown {
		if b.State != BFDAdminDown {
			tk.LogIt(tk.LogInfo, "%s: BFD State -> AdminDown\n", b.RemoteName)
		}
		b.State = BFDInit
	} else if raw.State == BFDUp {
		if b.State != BFDUp {
			tk.LogIt(tk.LogInfo, "%s: BFD State -> UP\n", b.RemoteName)
		}
		b.State = BFDUp
		if b.CiState == cmn.CIMasterStateString {
			// Force reelection
			if b.MyDisc <= b.RemDisc {
				oldState = BFDDown
			}
		}
	}
	notify := b.stateNotificationLocked(b.State, oldState)
	b.Mutex.Unlock()
	if notify != nil {
		notify()
	}
}

func (b *bfdSession) checkSessTimeout() {
	if err := b.takeOperation(0); err != nil {
		return
	}
	defer func() { <-b.ops }()
	b.Mutex.Lock()
	if b.stopping {
		b.Mutex.Unlock()
		return
	}
	oldState := b.State
	if b.State == BFDUp {
		if time.Duration(time.Since(b.LastRxTS).Microseconds()) > time.Duration(b.TimeOut) {
			b.State = BFDDown
			b.MyDisc = b.RemDisc + BFDIncrDiscVal
			tk.LogIt(tk.LogInfo, "%s: BFD State -> Down (%v:%v)\n", b.RemoteName, b.MyDisc, b.RemDisc)
		}
	}
	notify := b.stateNotificationLocked(b.State, oldState)
	b.Mutex.Unlock()
	if notify != nil {
		notify()
	}
}

// Called under Mutex and the operation token. Capture the callback arguments
// before unlocking; notifier calls never hold Mutex or the BFD table lock.
func (b *bfdSession) stateNotificationLocked(newState, oldState SessionState) func() {
	if newState == oldState || b.RemDisc == 0 {
		return nil
	}
	var ciState string
	if newState == BFDUp {
		ciState = cmn.CIBackupStateString
		if b.MyDisc > b.RemDisc {
			ciState = cmn.CIMasterStateString
		}
		tk.LogIt(tk.LogInfo, "%s: State change (%v:%v)\n", b.RemoteName, b.MyDisc, b.RemDisc)
	} else if newState == BFDDown && oldState == BFDUp {
		ciState = cmn.CIMasterStateString
	} else if b.RemDisc == b.MyDisc {
		ciState = cmn.CIUnDefStateString
	} else {
		return nil
	}
	b.CiState = ciState
	notify, inst, remote := b.Notify, b.Instance, b.RemoteName
	if notify == nil {
		return nil
	}
	return func() { notify.BFDSessionNotify(inst, remote, ciState) }
}

func (b *bfdSession) active() bool {
	b.Mutex.RLock()
	defer b.Mutex.RUnlock()
	return !b.stopping && b.gateOpen()
}

func (b *bfdSession) gateOpen() bool {
	if b.StartGate == nil {
		return true
	}
	select {
	case <-b.StartGate:
		return true
	default:
		return false
	}
}

func (b *bfdSession) bfdSessionTicker() {
	defer b.work.Done()
	defer b.TxTicker.Stop()
	defer b.RxTicker.Stop()
	if b.StartGate != nil {
		select {
		case <-b.StartGate:
		case <-b.Fin:
			return
		}
	}

	b.Mutex.Lock()
	if b.stopping {
		b.Mutex.Unlock()
		return
	}
	b.started = true
	b.Mutex.Unlock()
	for {
		select {
		case <-b.Fin:
			return
		case t := <-b.RxTicker.C:
			tk.LogIt(-1, "Tick at %v\n", t)
			b.checkSessTimeout()
		case t := <-b.TxTicker.C:
			tk.LogIt(-1, "Tick at %v\n", t)
			b.encodeCtrlPacket()
			b.sendBFDPacket()
		}
	}
}

// getMyDisc - Get My Discriminator based on remote
func getMyDisc(ip net.IP) net.IP {
	// get list of available addresses
	addr, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var first net.IP

	for _, addr := range addr {
		if ipnet, ok := addr.(*net.IPNet); ok {
			// check if IPv4 or IPv6 is not nil
			if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
				if ipnet.Contains(ip) {
					tk.LogIt(tk.LogDebug, "bfd mydisc : %s\n", ipnet.IP.String())
					return ipnet.IP
				}
				if first == nil {
					first = ipnet.IP
				}
			}
		}
	}

	tk.LogIt(tk.LogDebug, "bfd mydisc : %s\n", first.String())

	return first
}

func (b *bfdSession) initialize(remoteIP string, sourceIP string, port uint16, interval uint32, multi uint8) error {
	var err error
	b.RemoteName = fmt.Sprintf("%s:%d", remoteIP, port)

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return errors.New("address malformed")
	}

	myIP := net.ParseIP(sourceIP)
	if myIP == nil {
		return errors.New("source address malformed")
	}

	if myIP.IsUnspecified() {
		myIP = getMyDisc(ip)
		if myIP == nil {
			return errors.New("my discriminator not found")
		}
	} else {
		tk.LogIt(tk.LogDebug, "using bfd bind mydisc  : %s\n", myIP.String())
	}
	b.MyIP = myIP
	b.MyDisc = tk.IPtonl(myIP)
	b.RemDisc = 0 //tk.IPtonl(ip)
	b.MyMulti = multi
	b.DesMinTxInt = interval
	b.ReqMinRxInt = interval
	b.ReqMinEchoInt = interval
	b.State = BFDDown

	b.Cxn, err = net.DialTimeout("udp4", b.RemoteName, 1*time.Second)
	if err != nil || b.Cxn == nil {
		return errors.New("failed to dial BFD")
	}

	b.Fin = make(chan bool)
	b.done = make(chan struct{})
	b.ops = make(chan struct{}, 1)
	b.work.Add(1)
	b.TxTicker = time.NewTicker(time.Duration(b.DesMinTxInt) * time.Microsecond)
	b.RxTicker = time.NewTicker(time.Duration(BFDMinSysRXIntervalUs) * time.Microsecond)

	go b.bfdSessionTicker()
	return nil
}

func (b *bfdSession) destruct() error {
	b.requestStop()
	timer := time.NewTimer(bfdSessionStopWait)
	defer timer.Stop()
	select {
	case <-b.done:
	case <-timer.C:
		return errors.New("bfd session stop timed out")
	}
	b.finalizeOnce.Do(func() {
		b.Mutex.Lock()
		b.State = BFDAdminDown
		started := b.started
		b.Mutex.Unlock()
		if started {
			b.encodeCtrlPacket()
			b.sendBFDPacket()
		}
		b.Cxn.Close()
	})
	return nil
}

func (b *bfdSession) encodeCtrlPacket() error {
	b.Mutex.Lock()
	defer b.Mutex.Unlock()

	b.PktDat[0] = byte(byte(0x1<<5) | byte(0))
	b.PktDat[1] = (uint8(b.State) << 6)
	b.PktDat[2] = b.MyMulti
	b.PktDat[3] = 24

	binary.BigEndian.PutUint32(b.PktDat[4:], uint32(b.MyDisc))
	binary.BigEndian.PutUint32(b.PktDat[8:], uint32(b.RemDisc))
	binary.BigEndian.PutUint32(b.PktDat[12:], uint32(b.DesMinTxInt))
	binary.BigEndian.PutUint32(b.PktDat[16:], uint32(b.ReqMinRxInt))
	binary.BigEndian.PutUint32(b.PktDat[20:], uint32(b.ReqMinEchoInt))

	return nil
}

func (b *bfdSession) sendBFDPacket() error {
	b.Mutex.RLock()
	packet, conn := b.PktDat, b.Cxn
	b.Mutex.RUnlock()
	if err := conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return err
	}
	_, err := conn.Write(packet[:])
	if err != nil {
		tk.LogIt(-1, "Error in sending %s\n", err)
	}
	return err
}
