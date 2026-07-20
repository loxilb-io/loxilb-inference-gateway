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
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// IPsec error codes
const (
	IPsecErrBase = iota - 9000
	IPsecConfigErr
	IPsecTunnelExistsErr
	IPsecTunnelNotFoundErr
	IPsecCertInvalidErr
	IPsecCertExistsErr
	IPsecCertNotFoundErr
	IPsecStrongSwanErr
	IPsecFileIOErr
)

// strongSwan default paths (can be overridden)
const (
	DefaultIPsecConfPath    = "/etc/ipsec.conf"
	DefaultIPsecSecretsPath = "/etc/ipsec.secrets"
	DefaultIPsecCertsDir    = "/etc/ipsec.d/certs"
	DefaultIPsecPrivateDir  = "/etc/ipsec.d/private"
	DefaultIPsecCACertsDir  = "/etc/ipsec.d/cacerts"
	IPsecCommandPath        = "ipsec"
	IPsecConfigBackupExt    = ".backup"
)

// IPsecH - Main IPsec handler structure
type IPsecH struct {
	// Configuration paths
	confPath    string
	secretsPath string
	certsDir    string
	privateDir  string
	caCertsDir  string

	// In-memory state
	config         cmn.IPsecConfig
	tunnels        map[string]*cmn.IPsecTunnel
	certificates   map[string]*cmn.IPsecCertificate
	caCertificates map[string]*cmn.IPsecCACertificate

	// XFRM monitor (stub for now)
	xfrmStub *IPsecXFRMStub

	// Reload management
	reloadPending   bool
	reloadTimer     *time.Timer
	reloadDebounce  time.Duration
	lastConfigHash  string
	lastSecretsHash string
	shutdownChan    chan struct{}
	configWg        sync.WaitGroup // Track in-flight config operations

	// State refresh throttling (guarded by mutex)
	lastStateRefresh time.Time

	// Synchronization
	mutex sync.RWMutex
}

// IPsecXFRMStub - Stub for XFRM monitoring (to be implemented later)
type IPsecXFRMStub struct {
	stats cmn.IPsecStats
	mutex sync.RWMutex
}

// NewIPsecH - Initialize IPsec handler
func NewIPsecH(customPaths ...string) *IPsecH {
	confPath := DefaultIPsecConfPath
	secretsPath := DefaultIPsecSecretsPath
	certsDir := DefaultIPsecCertsDir
	privateDir := DefaultIPsecPrivateDir
	caCertsDir := DefaultIPsecCACertsDir

	// Allow custom paths for testing
	if len(customPaths) >= 5 {
		confPath = customPaths[0]
		secretsPath = customPaths[1]
		certsDir = customPaths[2]
		privateDir = customPaths[3]
		caCertsDir = customPaths[4]
	}

	h := &IPsecH{
		confPath:       confPath,
		secretsPath:    secretsPath,
		certsDir:       certsDir,
		privateDir:     privateDir,
		caCertsDir:     caCertsDir,
		tunnels:        make(map[string]*cmn.IPsecTunnel),
		certificates:   make(map[string]*cmn.IPsecCertificate),
		caCertificates: make(map[string]*cmn.IPsecCACertificate),
		xfrmStub:       &IPsecXFRMStub{},
		reloadDebounce: 500 * time.Millisecond, // Batch changes within 500ms
		shutdownChan:   make(chan struct{}),
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Handler initialized with reload debounce: %v\n", h.reloadDebounce)

	// Initialize default configuration
	h.config = cmn.IPsecConfig{
		FastPathEnabled:       false,
		HwOffloadEnabled:      false,
		HwOffloadType:         "none",
		AntiReplayEnabled:     true,
		SALifetimeWarnSeconds: 300,
		SeqOverflowAction:     "drop",
		MTU:                   1400,
		SupportedAlgorithms: []string{
			"aes128", "aes256", "3des",
			"sha1", "sha256", "sha512",
			"modp1024", "modp2048", "modp4096",
		},
	}

	// Create directories if they don't exist
	h.ensureDirectories()

	// Load existing configuration
	h.loadExistingConfig()

	tk.LogIt(tk.LogInfo, "[IPsec] Handler initialized (conf=%s)\n", confPath)

	return h
}

// Shutdown - Clean up IPsec handler resources
func (h *IPsecH) Shutdown() {
	tk.LogIt(tk.LogInfo, "[IPsec] Shutting down handler...\n")

	h.mutex.Lock()
	// Cancel any pending reload
	if h.reloadTimer != nil {
		h.reloadTimer.Stop()
	}

	// Signal shutdown
	close(h.shutdownChan)
	h.mutex.Unlock()

	// Wait for all in-flight configuration operations to complete
	tk.LogIt(tk.LogInfo, "[IPsec] Waiting for in-flight operations...\n")
	h.configWg.Wait()

	tk.LogIt(tk.LogInfo, "[IPsec] Handler shutdown complete\n")
}

// ensureDirectories - Create IPsec directories if they don't exist
func (h *IPsecH) ensureDirectories() {
	dirs := []string{h.certsDir, h.privateDir, h.caCertsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] Failed to create directory %s: %v\n", dir, err)
		}
	}
}

// loadExistingConfig - Load existing strongSwan configuration on startup
func (h *IPsecH) loadExistingConfig() {
	// Parse existing ipsec.conf if it exists
	if _, err := os.Stat(h.confPath); err == nil {
		// TODO: Parse existing config (low priority for now)
		tk.LogIt(tk.LogDebug, "[IPsec] Existing config found at %s\n", h.confPath)
	}
}

// NetIPsecGetConfig - Get global IPsec configuration
func (h *IPsecH) NetIPsecGetConfig() (*cmn.IPsecConfig, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	config := h.config
	return &config, nil
}

// NetIPsecConfigSet - Update global IPsec configuration
func (h *IPsecH) NetIPsecConfigSet(cfg *cmn.IPsecConfigMod) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if cfg.FastPathEnabled != nil {
		h.config.FastPathEnabled = *cfg.FastPathEnabled
	}
	if cfg.HwOffloadEnabled != nil {
		h.config.HwOffloadEnabled = *cfg.HwOffloadEnabled
	}
	if cfg.HwOffloadType != nil {
		h.config.HwOffloadType = *cfg.HwOffloadType
	}
	if cfg.AntiReplayEnabled != nil {
		h.config.AntiReplayEnabled = *cfg.AntiReplayEnabled
	}
	if cfg.SALifetimeWarnSeconds != nil {
		h.config.SALifetimeWarnSeconds = *cfg.SALifetimeWarnSeconds
	}
	if cfg.SeqOverflowAction != nil {
		h.config.SeqOverflowAction = *cfg.SeqOverflowAction
	}
	if cfg.MTU != nil {
		h.config.MTU = *cfg.MTU
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Config updated: FastPath=%v, HwOffload=%v\n",
		h.config.FastPathEnabled, h.config.HwOffloadEnabled)

	return 0, nil
}

// NetIPsecTunnelAdd - Create a new IPsec tunnel
func (h *IPsecH) NetIPsecTunnelAdd(tm *cmn.IPsecTunnelMod) (int, error) {
	h.mutex.Lock()
	// Don't defer unlock - we release it manually before async operations

	// Validate tunnel parameters
	if err := h.validateTunnelMod(tm); err != nil {
		h.mutex.Unlock()
		return IPsecConfigErr, err
	}

	// Check if tunnel already exists
	if _, exists := h.tunnels[tm.Name]; exists {
		h.mutex.Unlock()
		tk.LogIt(tk.LogError, "[IPsec] Tunnel %s already exists\n", tm.Name)
		return IPsecTunnelExistsErr, fmt.Errorf("tunnel %s already exists", tm.Name)
	}

	// Create tunnel object
	tunnel := &cmn.IPsecTunnel{
		IPsecTunnelMod: *tm,
		State:          "down",
		InstalledAt:    time.Now(),
	}

	// Apply default values for VTI parameters if not specified
	if tunnel.Mark == 0 {
		tunnel.Mark = 100 // Default VTI mark
	}
	if tunnel.TunnelMode == "" {
		tunnel.TunnelMode = "tunnel" // Default to tunnel mode
	}
	// installPolicy should default to true for marked VTI tunnels
	// - installpolicy=yes: strongSwan installs XFRM policies with mark
	// - disable_policy=1 on VTI: Interface ignores unmarked policies
	// - Together: Only marked traffic (routed via VTI) enters tunnel
	// compress defaults to false
	// mobike defaults to false
	// rekey defaults to true (handled in generateStrongSwanConfig)
	// reauth defaults to false

	// Add to in-memory state
	h.tunnels[tm.Name] = tunnel

	tk.LogIt(tk.LogInfo, "[IPsec] Generating strongSwan config for tunnel %s...\n", tm.Name)

	// Generate strongSwan configuration
	if err := h.generateStrongSwanConfig(); err != nil {
		delete(h.tunnels, tm.Name)
		h.mutex.Unlock()
		tk.LogIt(tk.LogError, "[IPsec] Config generation failed: %v\n", err)
		return IPsecStrongSwanErr, err
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Config generated successfully\n")

	// Generate secrets file (for PSK)
	secretsUpdated := false
	if tm.AuthMode == "psk" && tm.PSK != "" {
		tk.LogIt(tk.LogInfo, "[IPsec] Generating secrets file...\n")
		if err := h.generateStrongSwanSecrets(tm.Name, tm.PSK, tm.LocalIP, tm.RemoteIP, tm.LocalID, tm.RemoteID, tm.Auto); err != nil {
			delete(h.tunnels, tm.Name)
			h.mutex.Unlock()
			tk.LogIt(tk.LogError, "[IPsec] Secrets generation failed: %v\n", err)
			return IPsecStrongSwanErr, err
		}
		tk.LogIt(tk.LogInfo, "[IPsec] Secrets file updated\n")
		secretsUpdated = true
	}

	// Schedule reload with debouncing (batches multiple rapid API calls)
	// Must be called while holding mutex
	h.scheduleReloadUnlocked(secretsUpdated)

	// Release mutex before async operations
	h.mutex.Unlock()

	// Set VTI disable_policy asynchronously after reload completes
	// Note: No need to call "ipsec up" - config has "auto=start" which automatically
	// brings up tunnels when daemon restarts. Calling "ipsec up" would create duplicates!
	h.ensureVTIDisablePolicyAsync(tm.Name, tunnel.Mark, h.reloadDebounce)

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s created: %s <-> %s (auth=%s)\n",
		tm.Name, tm.LocalIP, tm.RemoteIP, tm.AuthMode)

	return 0, nil
}

// NetIPsecTunnelDel - Delete an IPsec tunnel
func (h *IPsecH) NetIPsecTunnelDel(name string) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Check if tunnel exists
	tunnel, exists := h.tunnels[name]
	if !exists {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel %s not found\n", name)
		return IPsecTunnelNotFoundErr, fmt.Errorf("tunnel %s not found", name)
	}

	// Remove PSK entry from secrets file if using PSK auth
	if tunnel.AuthMode == "psk" {
		tk.LogIt(tk.LogInfo, "[IPsec] Removing PSK entry for tunnel %s...\n", name)
		if err := h.removeSecretsEntry(tunnel.LocalIP, tunnel.RemoteIP, tunnel.LocalID, tunnel.RemoteID, tunnel.Auto); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] Failed to remove secrets entry: %v\n", err)
			// Continue anyway - config will be regenerated
		}
	}

	// Explicitly flush XFRM state/policies for this tunnel
	// This prevents orphaned XFRM entries if strongSwan restart fails
	if tunnel.Mark != 0 {
		tk.LogIt(tk.LogDebug, "[IPsec] Flushing XFRM entries for tunnel %s (mark=%d)\n", name, tunnel.Mark)
		// Flush XFRM state
		cmd := exec.Command("ip", "xfrm", "state", "flush")
		if output, err := cmd.CombinedOutput(); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] XFRM state flush warning: %v, output: %s\n", err, string(output))
		}
		// Flush XFRM policies
		cmd = exec.Command("ip", "xfrm", "policy", "flush")
		if output, err := cmd.CombinedOutput(); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] XFRM policy flush warning: %v, output: %s\n", err, string(output))
		}
	}

	// Remove from in-memory state
	delete(h.tunnels, name)

	// Regenerate configuration
	if err := h.generateStrongSwanConfig(); err != nil {
		return IPsecStrongSwanErr, err
	}

	// Schedule reload with debouncing (batches multiple rapid deletions)
	needSecretsReload := tunnel.AuthMode == "psk"
	h.scheduleReloadUnlocked(needSecretsReload)

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s deleted\n", name)

	return 0, nil
}

// NetIPsecTunnelUpdate - Update an existing IPsec tunnel in place
// Delete+add semantics under one lock: a single config regeneration and a
// single strongSwan reload, so there is no delete/recreate window where the
// tunnel is missing from the configuration.
func (h *IPsecH) NetIPsecTunnelUpdate(tm *cmn.IPsecTunnelMod) (int, error) {
	h.mutex.Lock()

	oldTunnel, exists := h.tunnels[tm.Name]
	if !exists {
		h.mutex.Unlock()
		tk.LogIt(tk.LogError, "[IPsec] Tunnel %s not found\n", tm.Name)
		return IPsecTunnelNotFoundErr, fmt.Errorf("tunnel %s not found", tm.Name)
	}

	// Carry over the stored PSK when the caller did not re-send it
	// (GET responses never include the PSK)
	if tm.AuthMode == "psk" && tm.PSK == "" && oldTunnel.AuthMode == "psk" {
		tm.PSK = oldTunnel.PSK
	}

	if err := h.validateTunnelMod(tm); err != nil {
		h.mutex.Unlock()
		return IPsecConfigErr, err
	}

	// Remove the old PSK entry - identifiers may have changed
	if oldTunnel.AuthMode == "psk" {
		if err := h.removeSecretsEntry(oldTunnel.LocalIP, oldTunnel.RemoteIP, oldTunnel.LocalID, oldTunnel.RemoteID, oldTunnel.Auto); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] Failed to remove old secrets entry: %v\n", err)
		}
	}

	tunnel := &cmn.IPsecTunnel{
		IPsecTunnelMod: *tm,
		State:          oldTunnel.State,
		InstalledAt:    oldTunnel.InstalledAt,
	}
	if tunnel.Mark == 0 {
		tunnel.Mark = 100
	}
	if tunnel.TunnelMode == "" {
		tunnel.TunnelMode = "tunnel"
	}

	h.tunnels[tm.Name] = tunnel

	if err := h.generateStrongSwanConfig(); err != nil {
		h.tunnels[tm.Name] = oldTunnel
		h.mutex.Unlock()
		tk.LogIt(tk.LogError, "[IPsec] Config generation failed: %v\n", err)
		return IPsecStrongSwanErr, err
	}

	// Old PSK entry was removed above, so a reload of secrets is needed
	// even when the new tunnel no longer uses PSK
	secretsUpdated := oldTunnel.AuthMode == "psk"
	if tm.AuthMode == "psk" && tm.PSK != "" {
		if err := h.generateStrongSwanSecrets(tm.Name, tm.PSK, tm.LocalIP, tm.RemoteIP, tm.LocalID, tm.RemoteID, tm.Auto); err != nil {
			h.tunnels[tm.Name] = oldTunnel
			h.mutex.Unlock()
			tk.LogIt(tk.LogError, "[IPsec] Secrets generation failed: %v\n", err)
			return IPsecStrongSwanErr, err
		}
		secretsUpdated = true
	}

	h.scheduleReloadUnlocked(secretsUpdated)
	h.mutex.Unlock()

	h.ensureVTIDisablePolicyAsync(tm.Name, tunnel.Mark, h.reloadDebounce)

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s updated: %s <-> %s (auth=%s)\n",
		tm.Name, tm.LocalIP, tm.RemoteIP, tm.AuthMode)

	return 0, nil
}

// NetIPsecTunnelAction - Execute a connection action on an existing tunnel
func (h *IPsecH) NetIPsecTunnelAction(name string, action string) (int, error) {
	h.mutex.RLock()
	_, exists := h.tunnels[name]
	h.mutex.RUnlock()
	if !exists {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel %s not found\n", name)
		return IPsecTunnelNotFoundErr, fmt.Errorf("tunnel %s not found", name)
	}

	var err error
	switch action {
	case "initiate":
		err = h.initiateConnection(name)
	case "terminate":
		err = h.terminateConnection(name)
	case "restart":
		if termErr := h.terminateConnection(name); termErr != nil {
			// A down tunnel has nothing to terminate - proceed to initiate
			tk.LogIt(tk.LogWarning, "[IPsec] Restart %s: terminate failed (continuing): %v\n", name, termErr)
		}
		err = h.initiateConnection(name)
	default:
		return IPsecConfigErr, fmt.Errorf("action must be 'initiate', 'terminate', or 'restart', got '%s'", action)
	}
	if err != nil {
		return IPsecStrongSwanErr, err
	}

	h.refreshTunnelStates(true)

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s action '%s' completed\n", name, action)

	return 0, nil
}

// NetIPsecTunnelGet - Get specific tunnel details
func (h *IPsecH) NetIPsecTunnelGet(name string) (*cmn.IPsecTunnel, error) {
	h.refreshTunnelStates(false)

	h.mutex.RLock()
	defer h.mutex.RUnlock()

	tunnel, exists := h.tunnels[name]
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", name)
	}

	// TODO: Update stats from XFRM when available
	tunnelCopy := *tunnel
	return &tunnelCopy, nil
}

// NetIPsecTunnelGetAll - Get all tunnels
func (h *IPsecH) NetIPsecTunnelGetAll() ([]*cmn.IPsecTunnel, error) {
	h.refreshTunnelStates(false)

	h.mutex.RLock()
	defer h.mutex.RUnlock()

	tunnels := make([]*cmn.IPsecTunnel, 0, len(h.tunnels))
	for _, tunnel := range h.tunnels {
		tunnelCopy := *tunnel
		tunnels = append(tunnels, &tunnelCopy)
	}

	return tunnels, nil
}

// NetIPsecTunnelPeerConfig - Generate the mirrored strongSwan configuration
// for the remote peer of an existing tunnel (left/right swapped), so the
// counterpart side can be brought up without hand-writing ipsec.conf
func (h *IPsecH) NetIPsecTunnelPeerConfig(name string) (*cmn.IPsecPeerConfig, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	tunnel, exists := h.tunnels[name]
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", name)
	}

	// Peer's local address is our remote and vice versa. When this side
	// accepts from anywhere, the peer auto-detects its own address.
	peerLeft := tunnel.RemoteIP
	if peerLeft == "%any" {
		peerLeft = "%defaultroute"
	}
	peerRight := tunnel.LocalIP
	if peerRight == "%defaultroute" || peerRight == "%config" {
		peerRight = "%any"
	}

	// Mirror the startup role: if we are the responder (add), the peer
	// initiates (start) and vice versa; on-demand (route) stays symmetric
	peerAuto := tunnel.Auto
	switch tunnel.Auto {
	case "add":
		peerAuto = "start"
	case "start":
		peerAuto = "add"
	}

	var conf strings.Builder
	conf.WriteString(fmt.Sprintf("# strongSwan peer configuration for tunnel %s\n", tunnel.Name))
	conf.WriteString("# Generated by loxilb - install on the REMOTE peer (append to /etc/ipsec.conf)\n\n")
	conf.WriteString(fmt.Sprintf("conn %s\n", tunnel.Name))
	if tunnel.IKEVersion == "ikev1" {
		conf.WriteString("    keyexchange=ikev1\n")
	} else {
		conf.WriteString("    keyexchange=ikev2\n")
	}
	conf.WriteString(fmt.Sprintf("    left=%s\n", peerLeft))
	conf.WriteString(fmt.Sprintf("    right=%s\n", peerRight))
	if tunnel.RemoteID != "" {
		conf.WriteString(fmt.Sprintf("    leftid=%s\n", tunnel.RemoteID))
	}
	if tunnel.LocalID != "" {
		conf.WriteString(fmt.Sprintf("    rightid=%s\n", tunnel.LocalID))
	}
	if tunnel.Selector.DstCIDR != "" {
		conf.WriteString(fmt.Sprintf("    leftsubnet=%s\n", tunnel.Selector.DstCIDR))
	}
	if tunnel.Selector.SrcCIDR != "" {
		conf.WriteString(fmt.Sprintf("    rightsubnet=%s\n", tunnel.Selector.SrcCIDR))
	}
	if tunnel.AuthMode == "psk" {
		conf.WriteString("    leftauth=psk\n")
		conf.WriteString("    rightauth=psk\n")
	} else {
		conf.WriteString("    authby=rsasig\n")
		conf.WriteString("    # leftcert=/etc/ipsec.d/certs/<peer-certificate>.pem\n")
	}

	// Identical proposals on both sides (incl. PFS group and compat fallback)
	ikeAlgo := fmt.Sprintf("%s-%s-%s", tunnel.IKEEncryption, tunnel.IKEIntegrity, tunnel.IKEDHGroup)
	espAlgo := fmt.Sprintf("%s-%s", tunnel.ESPEncryption, tunnel.ESPIntegrity)
	if tunnel.ESPDHGroup != "" {
		espAlgo += "-" + tunnel.ESPDHGroup
	}
	if tunnel.CompatFallback {
		ikeAlgo += ",aes128-sha1-modp1024"
		espAlgo += ",aes128-sha1"
	}
	conf.WriteString(fmt.Sprintf("    ike=%s!\n", ikeAlgo))
	conf.WriteString(fmt.Sprintf("    esp=%s!\n", espAlgo))

	conf.WriteString(fmt.Sprintf("    ikelifetime=%ds\n", tunnel.IKELifetime))
	conf.WriteString(fmt.Sprintf("    lifetime=%ds\n", tunnel.ESPLifetime))
	conf.WriteString(fmt.Sprintf("    dpdaction=%s\n", tunnel.DPD.Action))
	conf.WriteString(fmt.Sprintf("    dpddelay=%ds\n", tunnel.DPD.Delay))
	conf.WriteString(fmt.Sprintf("    dpdtimeout=%ds\n", tunnel.DPD.Timeout))
	if tunnel.TunnelMode != "" {
		conf.WriteString(fmt.Sprintf("    type=%s\n", tunnel.TunnelMode))
	}
	if tunnel.Compress {
		conf.WriteString("    compress=yes\n")
	} else {
		conf.WriteString("    compress=no\n")
	}
	if tunnel.Mobike {
		conf.WriteString("    mobike=yes\n")
	} else {
		conf.WriteString("    mobike=no\n")
	}
	conf.WriteString(fmt.Sprintf("    auto=%s\n", peerAuto))
	if tunnel.Rekey {
		conf.WriteString("    rekey=yes\n")
	} else {
		conf.WriteString("    rekey=no\n")
	}
	if tunnel.Reauth {
		conf.WriteString("    reauth=yes\n")
	} else {
		conf.WriteString("    reauth=no\n")
	}

	// Secrets entry, mirrored the same way generateStrongSwanSecrets builds ours
	secrets := ""
	if tunnel.AuthMode == "psk" {
		if tunnel.RemoteID != "" && tunnel.LocalID != "" {
			secrets = fmt.Sprintf("%s %s : PSK \"%s\"", tunnel.RemoteID, tunnel.LocalID, tunnel.PSK)
		} else if tunnel.LocalID != "" {
			secrets = fmt.Sprintf("%s : PSK \"%s\"", tunnel.LocalID, tunnel.PSK)
		} else {
			secrets = fmt.Sprintf("%s %s : PSK \"%s\"", tunnel.RemoteIP, tunnel.LocalIP, tunnel.PSK)
		}
	}

	notes := "Install the conn block in /etc/ipsec.conf on the remote peer, then run 'ipsec reload'."
	if tunnel.AuthMode == "psk" {
		notes += " Append the ipsecSecrets entry to /etc/ipsec.secrets and run 'ipsec rereadsecrets'. Keep the PSK confidential."
	} else {
		notes += " Certificate mode: install the peer certificate, its private key (referenced from /etc/ipsec.secrets, e.g. ': RSA peer.key'), and the CA certificate in /etc/ipsec.d/ on the remote peer."
	}
	if peerAuto == "start" {
		notes += " The peer initiates: run 'ipsec up " + tunnel.Name + "' or wait for auto=start."
	}
	if tunnel.Mark != 0 {
		notes += fmt.Sprintf(" This gateway routes via a VTI interface (mark %d); configure an equivalent VTI on the peer for route-based IPsec if needed.", tunnel.Mark)
	}

	return &cmn.IPsecPeerConfig{
		TunnelName:   tunnel.Name,
		IPsecConf:    conf.String(),
		IPsecSecrets: secrets,
		Notes:        notes,
	}, nil
}

// validateTunnelMod - Validate tunnel parameters
func (h *IPsecH) validateTunnelMod(tm *cmn.IPsecTunnelMod) error {
	if tm.Name == "" {
		return errors.New("tunnel name is required")
	}
	if tm.LocalIP == "" || tm.RemoteIP == "" {
		return errors.New("local_ip and remote_ip are required")
	}

	// Allow strongSwan special values for road warrior VPN:
	// %any - accept connections from any IP (server side)
	// %defaultroute - auto-detect local IP from default route (client side)
	// %config - use virtual IP from configuration
	// Otherwise validate as normal IP address
	specialValues := map[string]bool{
		"%any":          true,
		"%defaultroute": true,
		"%config":       true,
	}

	if !specialValues[tm.LocalIP] {
		if net.ParseIP(tm.LocalIP) == nil {
			return fmt.Errorf("local_ip must be valid IP or strongSwan special value (%%any, %%defaultroute, %%config), got '%s'", tm.LocalIP)
		}
	}

	if !specialValues[tm.RemoteIP] {
		if net.ParseIP(tm.RemoteIP) == nil {
			return fmt.Errorf("remote_ip must be valid IP or strongSwan special value (%%any, %%defaultroute, %%config), got '%s'", tm.RemoteIP)
		}
	}

	if tm.AuthMode != "psk" && tm.AuthMode != "cert" {
		return errors.New("auth_mode must be 'psk' or 'cert'")
	}
	if tm.AuthMode == "psk" && tm.PSK == "" {
		return errors.New("psk is required for psk authentication")
	}
	if tm.AuthMode == "cert" {
		if tm.CertName == "" {
			return errors.New("cert_name is required for cert authentication")
		}
		// Verify certificate exists
		if _, exists := h.certificates[tm.CertName]; !exists {
			return fmt.Errorf("certificate %s not found", tm.CertName)
		}
	}

	// Set defaults
	if tm.IKEVersion == "" {
		tm.IKEVersion = "ikev2"
	}
	if tm.IKEEncryption == "" {
		tm.IKEEncryption = "aes256"
	}
	if tm.IKEIntegrity == "" {
		tm.IKEIntegrity = "sha256"
	}
	if tm.IKEDHGroup == "" {
		tm.IKEDHGroup = "modp2048"
	}
	if tm.IKELifetime == 0 {
		tm.IKELifetime = 28800 // 8 hours
	}
	if tm.ESPEncryption == "" {
		tm.ESPEncryption = "aes256"
	}
	if tm.ESPIntegrity == "" {
		tm.ESPIntegrity = "sha256"
	}
	if tm.ESPLifetime == 0 {
		tm.ESPLifetime = 3600 // 1 hour
	}

	// Set DPD defaults
	if tm.DPD.Action == "" {
		tm.DPD.Action = "restart"
	}
	if tm.DPD.Delay == 0 {
		tm.DPD.Delay = 30
	}
	if tm.DPD.Timeout == 0 {
		tm.DPD.Timeout = 120
	}

	// Set Auto default and validate
	if tm.Auto == "" {
		tm.Auto = "start"
	}
	if tm.Auto != "start" && tm.Auto != "add" && tm.Auto != "route" {
		return fmt.Errorf("auto must be 'start', 'add', or 'route', got '%s'", tm.Auto)
	}

	return nil
}

// generateStrongSwanConfig - Generate ipsec.conf from in-memory state
func (h *IPsecH) generateStrongSwanConfig() error {
	// Backup existing config
	if _, err := os.Stat(h.confPath); err == nil {
		backupPath := h.confPath + IPsecConfigBackupExt
		if err := os.Rename(h.confPath, backupPath); err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] Failed to backup config: %v\n", err)
		}
	}

	// Build configuration
	var config strings.Builder
	config.WriteString("# strongSwan configuration generated by loxilb\n")
	config.WriteString("# DO NOT EDIT MANUALLY - changes will be overwritten\n\n")

	config.WriteString("config setup\n")
	config.WriteString("    charondebug=\"ike 2, knl 2, cfg 2\"\n")
	config.WriteString("    uniqueids=no\n\n")

	// Generate conn entries for each tunnel
	for _, tunnel := range h.tunnels {
		config.WriteString(fmt.Sprintf("conn %s\n", tunnel.Name))

		// IKE version
		if tunnel.IKEVersion == "ikev1" {
			config.WriteString("    keyexchange=ikev1\n")
		} else {
			config.WriteString("    keyexchange=ikev2\n")
		}

		// Endpoints
		config.WriteString(fmt.Sprintf("    left=%s\n", tunnel.LocalIP))
		config.WriteString(fmt.Sprintf("    right=%s\n", tunnel.RemoteIP))

		// Local/Remote IDs
		if tunnel.LocalID != "" {
			config.WriteString(fmt.Sprintf("    leftid=%s\n", tunnel.LocalID))
		}
		if tunnel.RemoteID != "" {
			config.WriteString(fmt.Sprintf("    rightid=%s\n", tunnel.RemoteID))
		}

		// Traffic selectors
		if tunnel.Selector.SrcCIDR != "" {
			config.WriteString(fmt.Sprintf("    leftsubnet=%s\n", tunnel.Selector.SrcCIDR))
		}
		if tunnel.Selector.DstCIDR != "" {
			config.WriteString(fmt.Sprintf("    rightsubnet=%s\n", tunnel.Selector.DstCIDR))
		}

		// Authentication
		if tunnel.AuthMode == "psk" {
			config.WriteString("    leftauth=psk\n")
			config.WriteString("    rightauth=psk\n")
		} else {
			config.WriteString("    authby=rsasig\n")
			if tunnel.CertName != "" {
				certPath := filepath.Join(h.certsDir, tunnel.CertName+".pem")
				config.WriteString(fmt.Sprintf("    leftcert=%s\n", certPath))
			}
		}

		// IKE/ESP proposals composed from single-token fields
		// IKE format: encryption-integrity-dhgroup (PRF auto-derived from integrity)
		// ESP format: encryption-integrity[-pfsgroup] (DH group present = PFS enabled)
		ikeAlgo := fmt.Sprintf("%s-%s-%s", tunnel.IKEEncryption, tunnel.IKEIntegrity, tunnel.IKEDHGroup)
		espAlgo := fmt.Sprintf("%s-%s", tunnel.ESPEncryption, tunnel.ESPIntegrity)
		if tunnel.ESPDHGroup != "" {
			espAlgo += "-" + tunnel.ESPDHGroup
		}
		if tunnel.CompatFallback {
			// Opt-in weak legacy proposal for interop with old peers
			ikeAlgo += ",aes128-sha1-modp1024"
			espAlgo += ",aes128-sha1"
		}
		config.WriteString(fmt.Sprintf("    ike=%s!\n", ikeAlgo))
		config.WriteString(fmt.Sprintf("    esp=%s!\n", espAlgo))

		// Lifetimes
		config.WriteString(fmt.Sprintf("    ikelifetime=%ds\n", tunnel.IKELifetime))
		config.WriteString(fmt.Sprintf("    lifetime=%ds\n", tunnel.ESPLifetime))

		// DPD
		config.WriteString(fmt.Sprintf("    dpdaction=%s\n", tunnel.DPD.Action))
		config.WriteString(fmt.Sprintf("    dpddelay=%ds\n", tunnel.DPD.Delay))
		config.WriteString(fmt.Sprintf("    dpdtimeout=%ds\n", tunnel.DPD.Timeout))

		// VTI-specific parameters (configurable via API with sensible defaults)
		if tunnel.Mark > 0 {
			config.WriteString(fmt.Sprintf("    mark=%d\n", tunnel.Mark))
		}
		if tunnel.TunnelMode != "" {
			config.WriteString(fmt.Sprintf("    type=%s\n", tunnel.TunnelMode))
		}
		if tunnel.InstallPolicy {
			config.WriteString("    installpolicy=yes\n")
		} else {
			config.WriteString("    installpolicy=no\n")
		}
		if tunnel.Compress {
			config.WriteString("    compress=yes\n")
		} else {
			config.WriteString("    compress=no\n")
		}
		if tunnel.Mobike {
			config.WriteString("    mobike=yes\n")
		} else {
			config.WriteString("    mobike=no\n")
		}

		// Auto-start mode (start=initiator/client, add=responder/server, route=on-demand)
		config.WriteString(fmt.Sprintf("    auto=%s\n", tunnel.Auto))
		config.WriteString("    closeaction=restart\n")
		if tunnel.Rekey {
			config.WriteString("    rekey=yes\n")
		} else {
			config.WriteString("    rekey=no\n")
		}
		if tunnel.Reauth {
			config.WriteString("    reauth=yes\n")
		} else {
			config.WriteString("    reauth=no\n")
		}
		config.WriteString("\n")
	}

	// Write configuration file
	if err := ioutil.WriteFile(h.confPath, []byte(config.String()), 0644); err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Failed to write config: %v\n", err)
		return fmt.Errorf("failed to write config: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Generated config with %d tunnel(s)\n", len(h.tunnels))

	return nil
}

// removeSecretsEntry - Remove a PSK entry from ipsec.secrets
func (h *IPsecH) removeSecretsEntry(localIP, remoteIP, localID, remoteID, autoMode string) error {
	// Determine which pattern to match based on configuration
	var pattern string
	if localID != "" {
		if autoMode == "add" && remoteID == "%any" {
			// Road warrior server: only local ID
			pattern = fmt.Sprintf("%s : PSK", localID)
		} else if remoteID != "" {
			// Both IDs specified
			pattern = fmt.Sprintf("%s %s : PSK", localID, remoteID)
		} else {
			// Just local ID
			pattern = fmt.Sprintf("%s : PSK", localID)
		}
	} else {
		// IP-based
		pattern = fmt.Sprintf("%s %s : PSK", localIP, remoteIP)
	}

	// Read existing secrets
	data, err := ioutil.ReadFile(h.secretsPath)
	if err != nil {
		// File doesn't exist, nothing to remove
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read secrets: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string

	for _, line := range lines {
		// Skip empty lines and comments (keep them)
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			newLines = append(newLines, line)
			continue
		}
		// Skip the line matching our pattern
		if !strings.Contains(line, pattern) {
			newLines = append(newLines, line)
		}
	}

	// Write updated secrets file
	if err := ioutil.WriteFile(h.secretsPath, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Failed to write secrets: %v\n", err)
		return fmt.Errorf("failed to write secrets: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Removed secret entry for %s\n", pattern)
	return nil
}

// generateStrongSwanSecrets - Generate ipsec.secrets for PSK authentication
func (h *IPsecH) generateStrongSwanSecrets(name, psk, localIP, remoteIP, localID, remoteID, autoMode string) error {
	// Determine the secrets pattern based on authentication type and role
	var secretLine string
	var matchPattern string

	if localID != "" {
		// ID-based authentication (road warrior or ID-based site-to-site)
		if autoMode == "add" && remoteID == "%any" {
			// Road warrior SERVER: Only specify local ID, accept any client
			secretLine = fmt.Sprintf("%s : PSK \"%s\"", localID, psk)
			matchPattern = fmt.Sprintf("%s : PSK", localID)
			tk.LogIt(tk.LogDebug, "[IPsec] Road warrior server secrets: %s\n", localID)
		} else if remoteID != "" {
			// Road warrior CLIENT or ID-based site-to-site: Both IDs
			secretLine = fmt.Sprintf("%s %s : PSK \"%s\"", localID, remoteID, psk)
			matchPattern = fmt.Sprintf("%s %s : PSK", localID, remoteID)
			tk.LogIt(tk.LogDebug, "[IPsec] ID-based secrets: %s <-> %s\n", localID, remoteID)
		} else {
			// Fallback: just local ID
			secretLine = fmt.Sprintf("%s : PSK \"%s\"", localID, psk)
			matchPattern = fmt.Sprintf("%s : PSK", localID)
			tk.LogIt(tk.LogDebug, "[IPsec] Single ID secrets: %s\n", localID)
		}
	} else {
		// IP-based authentication (traditional site-to-site)
		secretLine = fmt.Sprintf("%s %s : PSK \"%s\"", localIP, remoteIP, psk)
		matchPattern = fmt.Sprintf("%s %s : PSK", localIP, remoteIP)
		tk.LogIt(tk.LogDebug, "[IPsec] IP-based secrets: %s <-> %s\n", localIP, remoteIP)
	}

	// Read existing secrets and filter out any existing entry
	existingLines := []string{}
	if data, err := ioutil.ReadFile(h.secretsPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Keep comments and empty lines
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				existingLines = append(existingLines, line)
				continue
			}
			// Skip if this line matches our pattern (prevent duplicates)
			if strings.Contains(trimmed, matchPattern) {
				continue
			}
			existingLines = append(existingLines, line)
		}
	}

	// Build secrets file
	var secrets strings.Builder
	// Add header if file was empty
	if len(existingLines) == 0 {
		secrets.WriteString("# This file holds shared secrets or RSA private keys for authentication.\n\n")
		secrets.WriteString("# RSA private key for this host, authenticating it to any other host\n")
		secrets.WriteString("# which knows the public part.\n\n\n")
	} else {
		for _, line := range existingLines {
			secrets.WriteString(line + "\n")
		}
	}
	secrets.WriteString(secretLine + "\n")

	// Write secrets file with restricted permissions
	if err := ioutil.WriteFile(h.secretsPath, []byte(secrets.String()), 0600); err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Failed to write secrets: %v\n", err)
		return fmt.Errorf("failed to write secrets: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Updated secrets for tunnel %s\n", name)

	return nil
}

// reloadStrongSwan - Reload strongSwan configuration
// ensureStrongSwanRunning - Ensure strongSwan daemon (charon) is running
// This must be called before using ipsec reload or ipsec up commands
func (h *IPsecH) ensureStrongSwanRunning() error {
	// Check if charon daemon is running
	cmd := exec.Command(IPsecCommandPath, "status")
	output, err := cmd.CombinedOutput()

	if err == nil && len(output) > 0 {
		// Daemon is running
		tk.LogIt(tk.LogDebug, "[IPsec] strongSwan daemon already running\n")
		return nil
	}

	// Daemon not running, start it
	tk.LogIt(tk.LogInfo, "[IPsec] Starting strongSwan daemon...\n")
	cmd = exec.Command(IPsecCommandPath, "start")
	output, err = cmd.CombinedOutput()

	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Failed to start strongSwan daemon: %v, output: %s\n", err, string(output))
		return fmt.Errorf("failed to start strongSwan daemon: %v", err)
	}

	tk.LogIt(tk.LogInfo, "[IPsec] strongSwan daemon started successfully\n")
	tk.LogIt(tk.LogDebug, "[IPsec] Start output: %s\n", string(output))

	// Wait a bit for daemon to initialize
	time.Sleep(500 * time.Millisecond)

	return nil
}

// reloadStrongSwan - Reload strongSwan configuration
// Uses restart instead of reload to prevent XFRM policy accumulation
// See docs-dev/IPSEC_ROOT_CAUSE_ANALYSIS.md for details
func (h *IPsecH) reloadStrongSwan() error {
	// Try systemctl restart first (cleanest approach, matches ipsec2 behavior)
	tk.LogIt(tk.LogDebug, "[IPsec] Executing: systemctl restart strongswan-starter\n")
	cmd := exec.Command("systemctl", "restart", "strongswan-starter")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Fallback to ipsec restart if systemctl not available
		tk.LogIt(tk.LogDebug, "[IPsec] systemctl not available, falling back to: ipsec restart\n")
		cmd = exec.Command(IPsecCommandPath, "restart")
		output, err = cmd.CombinedOutput()

		if err != nil {
			tk.LogIt(tk.LogError, "[IPsec] strongSwan restart failed: %v, output: %s\n", err, string(output))
			return fmt.Errorf("strongSwan restart failed: %v", err)
		}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] strongSwan restart output: %s\n", string(output))
	tk.LogIt(tk.LogInfo, "[IPsec] strongSwan restarted successfully (clean XFRM state)\n")

	// Wait for daemon to be fully ready
	time.Sleep(1 * time.Second)

	return nil
}

// rereadStrongSwanSecrets - Reload strongSwan secrets file
func (h *IPsecH) rereadStrongSwanSecrets() error {
	tk.LogIt(tk.LogDebug, "[IPsec] Executing: ipsec rereadsecrets\n")
	cmd := exec.Command(IPsecCommandPath, "rereadsecrets")

	// Set a timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, IPsecCommandPath, "rereadsecrets")

	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			tk.LogIt(tk.LogError, "[IPsec] strongSwan rereadsecrets timeout after 5s\n")
			return fmt.Errorf("strongSwan rereadsecrets timeout")
		}
		tk.LogIt(tk.LogError, "[IPsec] strongSwan rereadsecrets failed: %v, output: %s\n", err, string(output))
		return fmt.Errorf("strongSwan rereadsecrets failed: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] strongSwan rereadsecrets output: %s\n", string(output))
	tk.LogIt(tk.LogDebug, "[IPsec] strongSwan secrets reloaded\n")

	return nil
}

// scheduleReloadUnlocked - Schedule a debounced reload (caller must hold h.mutex)
func (h *IPsecH) scheduleReloadUnlocked(needSecretsReload bool) {
	// If a reload is already pending, just update the timer
	if h.reloadPending {
		if h.reloadTimer != nil {
			h.reloadTimer.Reset(h.reloadDebounce)
		}
		tk.LogIt(tk.LogDebug, "[IPsec] Reload already scheduled, resetting timer\n")
		return
	}

	// Mark reload as pending
	h.reloadPending = true

	tk.LogIt(tk.LogInfo, "[IPsec] Scheduling reload in %v (batching changes)...\n", h.reloadDebounce)

	// Create a timer to execute reload after debounce period
	h.reloadTimer = time.AfterFunc(h.reloadDebounce, func() {
		h.executeScheduledReload(needSecretsReload)
	})
}

// executeScheduledReload - Actually perform the reload operation
func (h *IPsecH) executeScheduledReload(needSecretsReload bool) {
	// Check if shutdown was requested
	select {
	case <-h.shutdownChan:
		tk.LogIt(tk.LogInfo, "[IPsec] Reload canceled (shutdown)\n")
		return
	default:
		// Continue with reload
	}

	h.mutex.Lock()
	h.reloadPending = false
	h.mutex.Unlock()

	tk.LogIt(tk.LogInfo, "[IPsec] Executing scheduled reload...\n")

	// Check if configuration actually changed
	configChanged, err := h.hasConfigChanged()
	if err != nil {
		tk.LogIt(tk.LogWarning, "[IPsec] Failed to check config changes: %v\n", err)
	}

	var secretsChanged bool
	if needSecretsReload {
		secretsChanged, err = h.hasSecretsChanged()
		if err != nil {
			tk.LogIt(tk.LogWarning, "[IPsec] Failed to check secrets changes: %v\n", err)
		}
	}

	// Only reload if something actually changed
	if !configChanged && !secretsChanged {
		tk.LogIt(tk.LogInfo, "[IPsec] No changes detected, skipping reload\n")
		return
	}

	if configChanged {
		tk.LogIt(tk.LogInfo, "[IPsec] Configuration changed, reloading strongSwan...\n")
		if err := h.reloadStrongSwan(); err != nil {
			tk.LogIt(tk.LogError, "[IPsec] Reload failed: %v\n", err)
			return
		}
	}

	if secretsChanged {
		// Small delay to ensure ipsec reload completes
		time.Sleep(100 * time.Millisecond)
		tk.LogIt(tk.LogInfo, "[IPsec] Secrets changed, reloading secrets...\n")
		if err := h.rereadStrongSwanSecrets(); err != nil {
			tk.LogIt(tk.LogError, "[IPsec] Secrets reload failed: %v\n", err)
			return
		}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Scheduled reload completed successfully\n")
}

// hasConfigChanged - Check if ipsec.conf has changed since last reload
func (h *IPsecH) hasConfigChanged() (bool, error) {
	data, err := ioutil.ReadFile(h.confPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Simple hash comparison (could use MD5/SHA256 for production)
	currentHash := fmt.Sprintf("%d", len(data)) // Simple length-based check

	// Lock when accessing shared state
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.lastConfigHash == currentHash {
		return false, nil
	}

	h.lastConfigHash = currentHash
	return true, nil
}

// hasSecretsChanged - Check if ipsec.secrets has changed since last reload
func (h *IPsecH) hasSecretsChanged() (bool, error) {
	data, err := ioutil.ReadFile(h.secretsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	currentHash := fmt.Sprintf("%d", len(data))

	// Lock when accessing shared state
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.lastSecretsHash == currentHash {
		return false, nil
	}

	h.lastSecretsHash = currentHash
	return true, nil
}

// isWaitECHILD - loxilb runs as PID 1 in the container and reaps children
// globally (SIGCHLD handler in loxinet.go); it can steal an exec.Cmd's exit
// status, making Wait fail with ECHILD even though the command ran fine.
// Callers treat this as non-fatal (output is still captured).
func isWaitECHILD(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no child processes")
}

// initiateConnection - Initiate a strongSwan IPsec connection
func (h *IPsecH) initiateConnection(name string) error {
	tk.LogIt(tk.LogDebug, "[IPsec] Executing: ipsec up %s\n", name)

	// Set a timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, IPsecCommandPath, "up", name)
	// The ipsec wrapper spawns children that inherit the output pipes; without
	// WaitDelay, CombinedOutput blocks past the context kill until they exit
	cmd.WaitDelay = 2 * time.Second

	output, err := cmd.CombinedOutput()

	if err != nil && !isWaitECHILD(err) {
		if ctx.Err() == context.DeadlineExceeded {
			tk.LogIt(tk.LogError, "[IPsec] Connection initiation timeout after 10s\n")
			return fmt.Errorf("connection initiation timeout")
		}
		tk.LogIt(tk.LogError, "[IPsec] Connection initiation failed: %v, output: %s\n", err, string(output))
		return fmt.Errorf("connection initiation failed: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Connection initiation output: %s\n", string(output))
	tk.LogIt(tk.LogInfo, "[IPsec] Connection %s initiated\n", name)

	return nil
}

// terminateConnection - Terminate a strongSwan IPsec connection
func (h *IPsecH) terminateConnection(name string) error {
	tk.LogIt(tk.LogDebug, "[IPsec] Executing: ipsec down %s\n", name)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, IPsecCommandPath, "down", name)
	cmd.WaitDelay = 2 * time.Second

	output, err := cmd.CombinedOutput()

	if err != nil && !isWaitECHILD(err) {
		if ctx.Err() == context.DeadlineExceeded {
			tk.LogIt(tk.LogError, "[IPsec] Connection termination timeout after 10s\n")
			return fmt.Errorf("connection termination timeout")
		}
		tk.LogIt(tk.LogError, "[IPsec] Connection termination failed: %v, output: %s\n", err, string(output))
		return fmt.Errorf("connection termination failed: %v", err)
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Connection termination output: %s\n", string(output))
	tk.LogIt(tk.LogInfo, "[IPsec] Connection %s terminated\n", name)

	return nil
}

// refreshTunnelStates - Refresh tunnel states from `ipsec status` output.
// Best-effort: on any error the stored states are left untouched. Unless
// forced, refreshes are throttled to once per 2 seconds (GET paths poll).
func (h *IPsecH) refreshTunnelStates(force bool) {
	h.mutex.RLock()
	recent := time.Since(h.lastStateRefresh) < 2*time.Second
	h.mutex.RUnlock()
	if recent && !force {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	statusCmd := exec.CommandContext(ctx, IPsecCommandPath, "status")
	statusCmd.WaitDelay = 2 * time.Second
	output, err := statusCmd.CombinedOutput()
	if err != nil && !isWaitECHILD(err) {
		tk.LogIt(tk.LogDebug, "[IPsec] State refresh skipped: %v\n", err)
		return
	}

	// IKE SA lines look like "tun1[3]: ESTABLISHED 17 seconds ago, ..."
	established := make(map[string]bool)
	connecting := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		idx := strings.Index(trimmed, "[")
		if idx <= 0 {
			continue
		}
		connName := trimmed[:idx]
		if strings.Contains(trimmed, "ESTABLISHED") {
			established[connName] = true
		} else if strings.Contains(trimmed, "CONNECTING") {
			connecting[connName] = true
		}
	}

	h.mutex.Lock()
	h.lastStateRefresh = time.Now()
	for name, tunnel := range h.tunnels {
		switch {
		case established[name]:
			tunnel.State = "up"
		case connecting[name]:
			tunnel.State = "connecting"
		default:
			tunnel.State = "down"
		}
	}
	h.mutex.Unlock()
}

// ensureVTIDisablePolicyAsync - After the scheduled reload completes, ensure
// disable_policy is set on the tunnel's VTI interface (critical for
// route-based IPsec: prevents XFRM policies interfering with normal routing)
func (h *IPsecH) ensureVTIDisablePolicyAsync(tunnelName string, mark uint32, reloadWait time.Duration) {
	h.configWg.Add(1)
	go func() {
		defer h.configWg.Done()

		// Wait for scheduled reload to complete
		select {
		case <-time.After(reloadWait + 1*time.Second):
			// Continue with configuration
		case <-h.shutdownChan:
			tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s config canceled (shutdown)\n", tunnelName)
			return
		}

		if mark != 0 {
			vtiName := fmt.Sprintf("vti%d", mark)
			sysctlKey := fmt.Sprintf("net.ipv4.conf.%s.disable_policy", vtiName)
			tk.LogIt(tk.LogDebug, "[IPsec] Ensuring %s=1 for VTI routing\n", sysctlKey)

			cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=1", sysctlKey))
			if output, err := cmd.CombinedOutput(); err != nil {
				tk.LogIt(tk.LogWarning, "[IPsec] Failed to set disable_policy: %v, output: %s\n", err, string(output))
			} else {
				tk.LogIt(tk.LogDebug, "[IPsec] VTI disable_policy set successfully\n")
			}
		}

		tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s config applied after reload\n", tunnelName)
	}()
}

// NetIPsecCertificateAdd - Upload and install certificate
func (h *IPsecH) NetIPsecCertificateAdd(cm *cmn.IPsecCertificateMod) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Validate certificate
	validation, err := h.validateCertificate(cm.CertificatePEM, cm.PrivateKeyPEM, cm.Passphrase)
	if err != nil {
		return IPsecCertInvalidErr, err
	}
	if !validation.Valid {
		return IPsecCertInvalidErr, fmt.Errorf("certificate validation failed: %v", validation.Errors)
	}

	// Check if certificate already exists
	if _, exists := h.certificates[cm.Name]; exists {
		tk.LogIt(tk.LogError, "[IPsec] Certificate %s already exists\n", cm.Name)
		return IPsecCertExistsErr, fmt.Errorf("certificate %s already exists", cm.Name)
	}

	// Write certificate file
	certPath := filepath.Join(h.certsDir, cm.Name+".pem")
	if err := ioutil.WriteFile(certPath, []byte(cm.CertificatePEM), 0644); err != nil {
		return IPsecFileIOErr, fmt.Errorf("failed to write certificate: %v", err)
	}

	// Write private key file
	keyPath := filepath.Join(h.privateDir, cm.Name+".key")
	if err := ioutil.WriteFile(keyPath, []byte(cm.PrivateKeyPEM), 0600); err != nil {
		os.Remove(certPath) // Cleanup cert file
		return IPsecFileIOErr, fmt.Errorf("failed to write private key: %v", err)
	}

	// Store metadata
	cert := &cmn.IPsecCertificate{
		Name:        cm.Name,
		Subject:     validation.Subject,
		Issuer:      validation.Issuer,
		Serial:      "",         // TODO: Extract from cert
		SAN:         []string{}, // TODO: Extract SANs
		KeyUsage:    []string{}, // TODO: Extract key usage
		Description: cm.Description,
	}
	h.certificates[cm.Name] = cert

	// Reload strongSwan certificates
	cmd := exec.Command(IPsecCommandPath, "rereadcerts")
	if output, err := cmd.CombinedOutput(); err != nil {
		tk.LogIt(tk.LogWarning, "[IPsec] rereadcerts failed: %v, output: %s\n", err, string(output))
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Certificate %s installed (subject=%s)\n", cm.Name, validation.Subject)

	return 0, nil
}

// NetIPsecCertificateDel - Delete certificate
func (h *IPsecH) NetIPsecCertificateDel(name string) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, exists := h.certificates[name]; !exists {
		return IPsecCertNotFoundErr, fmt.Errorf("certificate %s not found", name)
	}

	// Remove files
	certPath := filepath.Join(h.certsDir, name+".pem")
	keyPath := filepath.Join(h.privateDir, name+".key")
	os.Remove(certPath)
	os.Remove(keyPath)

	// Remove from memory
	delete(h.certificates, name)

	tk.LogIt(tk.LogInfo, "[IPsec] Certificate %s deleted\n", name)

	return 0, nil
}

// NetIPsecCertificateGet - Get certificate details
func (h *IPsecH) NetIPsecCertificateGet(name string) (*cmn.IPsecCertificate, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	cert, exists := h.certificates[name]
	if !exists {
		return nil, fmt.Errorf("certificate %s not found", name)
	}

	certCopy := *cert
	return &certCopy, nil
}

// NetIPsecCertificateGetAll - Get all certificates
func (h *IPsecH) NetIPsecCertificateGetAll() ([]*cmn.IPsecCertificate, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	certs := make([]*cmn.IPsecCertificate, 0, len(h.certificates))
	for _, cert := range h.certificates {
		certCopy := *cert
		certs = append(certs, &certCopy)
	}

	return certs, nil
}

// NetIPsecCertificateExportAll - Export all certificates WITH PEM material
// (certificate + private key read back from disk) for snapshot round-trip.
// SENSITIVE: only the snapshot/restore path may serve this.
func (h *IPsecH) NetIPsecCertificateExportAll() ([]cmn.IPsecCertificateMod, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	mods := make([]cmn.IPsecCertificateMod, 0, len(h.certificates))
	for name, cert := range h.certificates {
		certPEM, err := ioutil.ReadFile(filepath.Join(h.certsDir, name+".pem"))
		if err != nil {
			return nil, fmt.Errorf("export certificate %s: read cert PEM: %v", name, err)
		}
		keyPEM, err := ioutil.ReadFile(filepath.Join(h.privateDir, name+".key"))
		if err != nil {
			return nil, fmt.Errorf("export certificate %s: read private key: %v", name, err)
		}
		mods = append(mods, cmn.IPsecCertificateMod{
			Name:           name,
			CertificatePEM: string(certPEM),
			PrivateKeyPEM:  string(keyPEM),
			Description:    cert.Description,
		})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	return mods, nil
}

// NetIPsecCertificateValidate - Validate certificate and private key
func (h *IPsecH) NetIPsecCertificateValidate(certPEM, keyPEM, passphrase string) (*cmn.IPsecCertValidation, error) {
	return h.validateCertificate(certPEM, keyPEM, passphrase)
}

// validateCertificate - Internal certificate validation
func (h *IPsecH) validateCertificate(certPEM, keyPEM, passphrase string) (*cmn.IPsecCertValidation, error) {
	validation := &cmn.IPsecCertValidation{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Parse certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		validation.Valid = false
		validation.Errors = append(validation.Errors, "Failed to decode PEM certificate")
		return validation, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		validation.Valid = false
		validation.Errors = append(validation.Errors, fmt.Sprintf("Failed to parse certificate: %v", err))
		return validation, nil
	}

	validation.Subject = cert.Subject.String()
	validation.Issuer = cert.Issuer.String()

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		validation.Valid = false
		validation.Errors = append(validation.Errors, "Certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		validation.Valid = false
		validation.Errors = append(validation.Errors, "Certificate expired")
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		validation.Warnings = append(validation.Warnings, "Certificate expires within 30 days")
	}

	// Parse private key
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		validation.Valid = false
		validation.Errors = append(validation.Errors, "Failed to decode PEM private key")
		return validation, nil
	}

	var privKey interface{}
	var keyAlgo string
	var keySize uint16

	// Try different key types
	if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		privKey = key
		keyAlgo = "RSA"
		keySize = uint16(key.N.BitLen())
	} else if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		privKey = key
		switch k := key.(type) {
		case *rsa.PrivateKey:
			keyAlgo = "RSA"
			keySize = uint16(k.N.BitLen())
		case *ecdsa.PrivateKey:
			keyAlgo = "ECDSA"
			keySize = uint16(k.Curve.Params().BitSize)
		}
	} else if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		privKey = key
		keyAlgo = "ECDSA"
		keySize = uint16(key.Curve.Params().BitSize)
	} else {
		validation.Valid = false
		validation.Errors = append(validation.Errors, "Failed to parse private key")
		return validation, nil
	}

	validation.KeyAlgorithm = keyAlgo
	validation.KeySize = int(keySize)

	// Verify key matches certificate
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if priv, ok := privKey.(*rsa.PrivateKey); ok {
			if pub.N.Cmp(priv.N) != 0 {
				validation.Valid = false
				validation.Errors = append(validation.Errors, "Private key does not match certificate")
			}
		}
	case *ecdsa.PublicKey:
		if priv, ok := privKey.(*ecdsa.PrivateKey); ok {
			if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
				validation.Valid = false
				validation.Errors = append(validation.Errors, "Private key does not match certificate")
			}
		}
	}

	// Check key size
	if keyAlgo == "RSA" && keySize < 2048 {
		validation.Warnings = append(validation.Warnings, "RSA key size < 2048 bits (not recommended)")
	}

	return validation, nil
}

// NetIPsecCACertificateAdd - Add CA certificate
func (h *IPsecH) NetIPsecCACertificateAdd(cm *cmn.IPsecCACertificateMod) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Parse and validate CA certificate
	block, _ := pem.Decode([]byte(cm.CertificatePEM))
	if block == nil {
		return IPsecCertInvalidErr, errors.New("failed to decode PEM CA certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return IPsecCertInvalidErr, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Check if it's a CA certificate
	if !cert.IsCA {
		return IPsecCertInvalidErr, errors.New("certificate is not a CA certificate")
	}

	// Check if already exists
	if _, exists := h.caCertificates[cm.Name]; exists {
		return IPsecCertExistsErr, fmt.Errorf("CA certificate %s already exists", cm.Name)
	}

	// Write CA certificate
	caCertPath := filepath.Join(h.caCertsDir, cm.Name+".pem")
	if err := ioutil.WriteFile(caCertPath, []byte(cm.CertificatePEM), 0644); err != nil {
		return IPsecFileIOErr, fmt.Errorf("failed to write CA certificate: %v", err)
	}

	// Store metadata
	caCert := &cmn.IPsecCACertificate{
		Name:        cm.Name,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Serial:      cert.SerialNumber.String(),
		Description: cm.Description,
	}
	h.caCertificates[cm.Name] = caCert

	// Reload strongSwan CA certificates
	cmd := exec.Command(IPsecCommandPath, "rereadcacerts")
	if output, err := cmd.CombinedOutput(); err != nil {
		tk.LogIt(tk.LogWarning, "[IPsec] rereadcacerts failed: %v, output: %s\n", err, string(output))
	}

	tk.LogIt(tk.LogInfo, "[IPsec] CA certificate %s installed\n", cm.Name)

	return 0, nil
}

// NetIPsecCACertificateDel - Delete CA certificate
func (h *IPsecH) NetIPsecCACertificateDel(name string) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, exists := h.caCertificates[name]; !exists {
		return IPsecCertNotFoundErr, fmt.Errorf("CA certificate %s not found", name)
	}

	// Remove file
	caCertPath := filepath.Join(h.caCertsDir, name+".pem")
	os.Remove(caCertPath)

	// Remove from memory
	delete(h.caCertificates, name)

	tk.LogIt(tk.LogInfo, "[IPsec] CA certificate %s deleted\n", name)

	return 0, nil
}

// NetIPsecCACertificateGet - Get CA certificate details
func (h *IPsecH) NetIPsecCACertificateGet(name string) (*cmn.IPsecCACertificate, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	caCert, exists := h.caCertificates[name]
	if !exists {
		return nil, fmt.Errorf("CA certificate %s not found", name)
	}

	caCertCopy := *caCert
	return &caCertCopy, nil
}

// NetIPsecCACertificateGetAll - Get all CA certificates
func (h *IPsecH) NetIPsecCACertificateGetAll() ([]*cmn.IPsecCACertificate, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	caCerts := make([]*cmn.IPsecCACertificate, 0, len(h.caCertificates))
	for _, caCert := range h.caCertificates {
		caCertCopy := *caCert
		caCerts = append(caCerts, &caCertCopy)
	}

	return caCerts, nil
}

// NetIPsecCACertificateExportAll - Export all CA certificates WITH PEM
// material (read back from disk) for snapshot round-trip.
func (h *IPsecH) NetIPsecCACertificateExportAll() ([]cmn.IPsecCACertificateMod, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	mods := make([]cmn.IPsecCACertificateMod, 0, len(h.caCertificates))
	for name, caCert := range h.caCertificates {
		certPEM, err := ioutil.ReadFile(filepath.Join(h.caCertsDir, name+".pem"))
		if err != nil {
			return nil, fmt.Errorf("export CA certificate %s: read PEM: %v", name, err)
		}
		mods = append(mods, cmn.IPsecCACertificateMod{
			Name:           name,
			CertificatePEM: string(certPEM),
			Description:    caCert.Description,
		})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	return mods, nil
}

// XFRM Stub methods (to be implemented in)

// NetIPsecSAGetAll - Get all Security Associations (stub)
func (h *IPsecH) NetIPsecSAGetAll() ([]*cmn.IPsecSA, error) {
	// TODO: Implement XFRM netlink query
	tk.LogIt(tk.LogDebug, "[IPsec] NetIPsecSAGetAll called (stub)\n")
	return []*cmn.IPsecSA{}, nil
}

// NetIPsecStatsGet - Get IPsec statistics (stub)
func (h *IPsecH) NetIPsecStatsGet() (*cmn.IPsecStats, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	// Basic stats from tunnel count
	stats := &cmn.IPsecStats{
		TotalTunnels:    len(h.tunnels),
		TunnelsUp:       0,
		TunnelsDown:     len(h.tunnels),
		TotalSAs:        0,
		TotalBytesIn:    0,
		TotalBytesOut:   0,
		TotalPacketsIn:  0,
		TotalPacketsOut: 0,
		EncryptErrors:   0,
		DecryptErrors:   0,
		AuthErrors:      0,
		ReplayErrors:    0,
		SeqOverflows:    0,
		LastUpdated:     time.Now(),
	}

	// TODO: Get real stats from XFRM

	return stats, nil
}

// NetIPsecStatsReset - Reset statistics (stub)
func (h *IPsecH) NetIPsecStatsReset() (int, error) {
	h.xfrmStub.mutex.Lock()
	defer h.xfrmStub.mutex.Unlock()

	h.xfrmStub.stats = cmn.IPsecStats{}

	tk.LogIt(tk.LogInfo, "[IPsec] Statistics reset\n")

	return 0, nil
}
