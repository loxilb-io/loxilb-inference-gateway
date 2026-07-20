/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

// KVAgentOptions defines CLI flags for the loxilb-kv-agent binary.
// Pattern follows options/options.go in the main loxilb project.
type KVAgentOptions struct {
	Listen       string `long:"listen" default:":9099" description:"REST API listen address"`
	DocaPCI      string `long:"doca-pci" default:"" description:"DOCA device PCI address (auto-detect if empty)"`
	KVStoreHost  string `long:"kv-store-host" default:"" description:"Default KV store host"`
	KVStorePort  uint16 `long:"kv-store-port" default:"6379" description:"Default KV store port"`
	StagingSize  uint64 `long:"staging-size" default:"4194304" description:"Staging buffer size in bytes (4MB)"`
	MgmtToken    string `long:"kv-mgmt-token" default:"/run/loxilb-kv/mgmt-token" description:"Path to REST management token file"`
	LogLevel     string `long:"log-level" default:"info" description:"Log level"`
	CoreAffinity string `long:"kv-core-affinity" default:"" description:"ARM core affinity groups: net_cores:deq_cores:ctrl_cores (e.g., 0,1:2,3,4,5:6,7). Empty enables auto-detect."`
}
