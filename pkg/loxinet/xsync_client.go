/*
 * Copyright (c) 2022 NetLOX Inc
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

package loxinet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/rpc"
	"strconv"
	"time"

	tk "github.com/loxilb-io/loxilib"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type netRPCClient struct {
	client *rpc.Client
}

type gRPCClient struct {
	conn    *grpc.ClientConn
	xclient XSyncClient
}

// XSyncClient returns the underlying XSyncClient.
// per-peer consumer goroutine needs to invoke SockproxySessionMod on the
// peer's gRPC client; the DpPeer.Client field is interface{} typed and
// this method provides a structural-typed accessor without forcing the
// loxinet package to import gRPC internals.
func (g gRPCClient) XSyncClient() XSyncClient {
	return g.xclient
}

// dialHTTPPath connects to an HTTP RPC server
// at the specified network address and path.
// This is based on rpc package's DialHTTPPath but with added timeout
func dialHTTPPath(network, address, path string) (*rpc.Client, error) {
	var connected = "200 Connected to Go RPC"
	timeOut := 2 * time.Second

	conn, err := net.DialTimeout(network, address, timeOut)
	if err != nil {
		return nil, err
	}
	io.WriteString(conn, "CONNECT "+path+" HTTP/1.0\n\n")

	// Require successful HTTP response
	// before switching to RPC protocol.
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err == nil && resp.Status == connected {
		return rpc.NewClient(conn), nil
	}
	if err == nil {
		err = errors.New("unexpected HTTP response: " + resp.Status)
	}
	conn.Close()
	return nil, &net.OpError{
		Op:   "dial-http",
		Net:  network + " " + address,
		Addr: nil,
		Err:  err,
	}
}

// DialXSyncGRPC opens a fresh gRPC connection to peerIP:SockproxyXSyncPort (22223)
// and returns the XSyncClient stub. The sockproxy xSync consumerLoop uses this
// dedicated port so that it speaks gRPC/HTTP2 independently of the CT-sync
// net/rpc path on XSyncPort (22222).
// Fix: changed from XSyncPort (22222, net/rpc HTTP/1.1) to
// SockproxyXSyncPort (22223, gRPC HTTP/2) so the protocol matches the server.
func DialXSyncGRPC(peerIP string) (XSyncClient, error) {
	cStr := net.JoinHostPort(peerIP, strconv.Itoa(SockproxyXSyncPort))
	if _, err := net.DialTimeout("tcp", cStr, 2*time.Second); err != nil {
		return nil, fmt.Errorf("TCP probe %s: %w", cStr, err)
	}
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.Dial(cStr, opts...)
	if conn == nil || err != nil {
		return nil, fmt.Errorf("gRPC dial %s: %w", cStr, err)
	}
	tk.LogIt(tk.LogInfo, "XSync gRPC sockproxy - %s :Connected\n", cStr)
	return NewXSyncClient(conn), nil
}

func netRPCConnect(pe *DpPeer) int {
	cStr := net.JoinHostPort(pe.Peer.String(), strconv.Itoa(XSyncPort))
	client, err := dialHTTPPath("tcp", cStr, rpc.DefaultRPCPath)
	if client == nil || err != nil {
		tk.LogIt(tk.LogInfo, "XSync netRPC Connect - %s :Fail(%s)\n", cStr, err)
		pe.Client = nil
		return -1
	}
	pe.Client = client
	tk.LogIt(tk.LogInfo, "XSync netRPC - %s :Connected\n", cStr)
	return 0
}

func (*netRPCClient) RPCConnect(pe *DpPeer) int {
	return netRPCConnect(pe)
}

func (*netRPCClient) RPCReset(pe *DpPeer) int {
	cStr := net.JoinHostPort(pe.Peer.String(), strconv.Itoa(XSyncPort))
	client, ok := pe.Client.(*rpc.Client)
	if ok && client != nil {
		client.Close()
		pe.Client = nil
	}
	if pe.Client == nil {
		tk.LogIt(tk.LogInfo, "XSync netRPC - %s :Reset\n", cStr)
		return netRPCConnect(pe)
	}
	return 0
}

func (*netRPCClient) RPCClose(pe *DpPeer) int {
	if pe.Client != nil {
		pe.Client.(*rpc.Client).Close()
	}
	pe.Client = nil
	return 0
}

func (*netRPCClient) RPCSend(pe *DpPeer, rpcCallStr string, args any) (int, error) {
	var reply int
	client, _ := pe.Client.(*rpc.Client)
	timeout := 2 * time.Second
	call := client.Go(rpcCallStr, args, &reply, make(chan *rpc.Call, 1))
	select {
	case <-time.After(timeout):
		tk.LogIt(tk.LogError, "netRPC call timeout(%v)\n", timeout)
		if pe.Client != nil {
			pe.Client.(*rpc.Client).Close()
		}
		pe.Client = nil

		return reply, errors.New("netrpc call timeout")
	case resp := <-call.Done:
		if resp != nil && resp.Error != nil {
			tk.LogIt(tk.LogError, "netRPC send failed(%s)\n", resp.Error)
			return reply, resp.Error
		}
	}
	return reply, nil
}

func gRPCConnect(pe *DpPeer) int {
	var err error
	var opts []grpc.DialOption
	var cinfo gRPCClient
	cStr := net.JoinHostPort(pe.Peer.String(), strconv.Itoa(XSyncPort))

	timeOut := 2 * time.Second

	_, err = net.DialTimeout("tcp", cStr, timeOut)
	if err != nil {
		tk.LogIt(tk.LogInfo, "Failed to dial xsync pair(%s): %v\n", cStr, err)
		return -1
	}

	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	cinfo.conn, err = grpc.Dial(cStr, opts...)

	if cinfo.conn == nil || err != nil {
		tk.LogIt(tk.LogInfo, "Failed to dial xsync gRPC pair: %v\n", err)
		return -1
	}

	cinfo.xclient = NewXSyncClient(cinfo.conn)
	pe.Client = cinfo
	tk.LogIt(tk.LogInfo, "XSync gRPC - %s :Connected\n", cStr)
	return 0
}

func (*gRPCClient) RPCConnect(pe *DpPeer) int {
	return gRPCConnect(pe)
}

func (*gRPCClient) RPCReset(pe *DpPeer) int {
	cStr := net.JoinHostPort(pe.Peer.String(), strconv.Itoa(XSyncPort))
	client, ok := pe.Client.(gRPCClient)
	if ok {
		client.conn.Close()
		pe.Client = nil
	}

	if pe.Client == nil {
		tk.LogIt(tk.LogInfo, "XSync gRPC - %s :Reset\n", cStr)
		return gRPCConnect(pe)
	}
	return 0
}

func (*gRPCClient) RPCClose(pe *DpPeer) int {
	if pe.Client != nil {
		pe.Client.(gRPCClient).conn.Close()
	}
	pe.Client = nil
	return 0
}

func (ci *DpCtInfo) ConvertToCtInfo(c *CtInfo) {
	c.Dip = ci.DIP
	c.Sip = ci.SIP
	c.Dport = int32(ci.Dport)
	c.Sport = int32(ci.Sport)
	c.Proto = ci.Proto
	c.Cstate = ci.CState
	c.Cact = ci.CAct
	c.Ci = ci.CI
	c.Packets = int64(ci.Packets)
	c.Bytes = int64(ci.Bytes)
	c.Deleted = int32(ci.Deleted)
	c.Pkey = ci.PKey
	c.Pval = ci.PVal
	c.Xsync = ci.XSync
	c.Serviceip = ci.ServiceIP
	c.Servproto = ci.ServProto
	c.L4Servport = int32(ci.L4ServPort)
	c.Blocknum = int32(ci.BlockNum)
}

func callGRPC(client XSyncClient, rpcCallStr string, args interface{}, reply *int) error {
	var err error
	var xreply *XSyncReply
	var ctis []*CtInfo
	var ct *CtInfo

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if (rpcCallStr == "XSync.DpWorkOnBlockCtAdd") ||
		(rpcCallStr == "XSync.DpWorkOnBlockCtDelete") {
		blkCtis := args.([]DpCtInfo)
		ctis = make([]*CtInfo, len(blkCtis))
		for i, c := range blkCtis {
			ctis[i] = &CtInfo{}
			c.ConvertToCtInfo(ctis[i])
		}
	} else if (rpcCallStr == "XSync.DpWorkOnCtAdd") ||
		(rpcCallStr == "XSync.DpWorkOnCtDelete") {
		c := args.(DpCtInfo)
		ct = &CtInfo{}
		c.ConvertToCtInfo(ct)
	}

	if rpcCallStr == "XSync.DpWorkOnBlockCtAdd" {
		xreply, err = client.DpWorkOnBlockCtModGRPC(ctx, &BlockCtInfoMod{Add: true, Ct: ctis})
	} else if rpcCallStr == "XSync.DpWorkOnBlockCtDelete" {
		xreply, err = client.DpWorkOnBlockCtModGRPC(ctx, &BlockCtInfoMod{Add: false, Ct: ctis})
	} else if rpcCallStr == "XSync.DpWorkOnCtAdd" {
		xreply, err = client.DpWorkOnCtModGRPC(ctx, &CtInfoMod{Add: true, Ct: ct})
	} else if rpcCallStr == "XSync.DpWorkOnCtDelete" {
		xreply, err = client.DpWorkOnCtModGRPC(ctx, &CtInfoMod{Add: false, Ct: ct})
	} else if rpcCallStr == "XSync.DpWorkOnCtGet" {
		xreply, err = client.DpWorkOnCtGetGRPC(ctx, &ConnGet{Async: args.(int32)})
	} else if rpcCallStr == "XSync.SockproxySessionMod" {
		// stub dispatch — coordinator (sockproxy_sync.go) owns the
		// real per-peer path. Accepts a pre-built *SockproxySessionModReq;
		// callers that don't pass one (e.g. legacy DpXsyncRPC funnel) get
		// an "not-implemented-yet" error so the path stays observable.
		if msg, ok := args.(*SockproxySessionModReq); ok {
			xreply, err = client.SockproxySessionMod(ctx, msg)
		} else {
			err = errors.New("not-implemented-yet")
		}
	} else if rpcCallStr == "XSync.SockproxySessionBulkGet" {
		if msg, ok := args.(*SockproxyBulkReq); ok {
			_, err = client.SockproxySessionBulkGet(ctx, msg)
		} else {
			err = errors.New("not-implemented-yet")
		}
	} else if rpcCallStr == "XSync.RateLimiterSync" {
		if msg, ok := args.(*RateLimiterBatch); ok {
			xreply, err = client.RateLimiterSync(ctx, msg)
		} else {
			err = errors.New("not-implemented-yet")
		}
	} else if rpcCallStr == "XSync.GetSockproxySnapshot" {
		if msg, ok := args.(*SockproxyBulkReq); ok {
			_, err = client.GetSockproxySnapshot(ctx, msg)
		} else {
			err = errors.New("not-implemented-yet")
		}
	}

	if err != nil {
		*reply = -1
		tk.LogIt(tk.LogError, "XSync %s reply - %v[NOK]\n", rpcCallStr, err.Error())
	} else if xreply != nil {
		*reply = int(xreply.Response)
		tk.LogIt(tk.LogDebug, "XSync %s peer reply - %d\n", rpcCallStr, *reply)
	}
	return err
}

func (*gRPCClient) RPCSend(pe *DpPeer, rpcCallStr string, args any) (int, error) {
	var reply int
	err := callGRPC(pe.Client.(gRPCClient).xclient, rpcCallStr, args, &reply)

	return reply, err
}
