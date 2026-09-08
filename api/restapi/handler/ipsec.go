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

package handler

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// Helper function to safely dereference uint32 pointers (ipsec-specific)
func derefUint32Ipsec(u *uint32) uint32 {
	if u == nil {
		return 0
	}
	return *u
}

// Helper function to safely dereference bool pointers
func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// Helper function to safely dereference bool pointers with true default (for installPolicy)
func derefBoolDefaultTrue(b *bool) bool {
	if b == nil {
		return true
	}
	return *b
}

// ConfigGetIPsec - Get IPsec configuration
func ConfigGetIPsec(params operations.GetConfigIpsecParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	config, err := ApiHooks.NetIPsecGetConfig()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get config[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get config[OK]: FastPath=%v, HwOffload=%v\n", config.FastPathEnabled, config.HwOffloadEnabled)

	// Convert to API model
	response := &models.IPsecConfig{
		FastPathEnabled:       config.FastPathEnabled,
		HwOffloadEnabled:      config.HwOffloadEnabled,
		HwOffloadType:         config.HwOffloadType,
		AntiReplayEnabled:     config.AntiReplayEnabled,
		SaLifetimeWarnSeconds: config.SALifetimeWarnSeconds,
		SeqOverflowAction:     config.SeqOverflowAction,
		Mtu:                   config.MTU,
		SupportedAlgorithms:   config.SupportedAlgorithms,
	}

	return operations.NewGetConfigIpsecOK().WithPayload(response)
}

// ConfigPostIPsec - Update IPsec configuration
func ConfigPostIPsec(params operations.PostConfigIpsecParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	cfgMod := cmn.IPsecConfigMod{
		FastPathEnabled:       &params.Attr.FastPathEnabled,
		HwOffloadEnabled:      &params.Attr.HwOffloadEnabled,
		HwOffloadType:         &params.Attr.HwOffloadType,
		AntiReplayEnabled:     &params.Attr.AntiReplayEnabled,
		SALifetimeWarnSeconds: &params.Attr.SaLifetimeWarnSeconds,
		SeqOverflowAction:     &params.Attr.SeqOverflowAction,
		MTU:                   &params.Attr.Mtu,
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Config update: FastPath=%v, HwOffload=%v\n",
		*cfgMod.FastPathEnabled, *cfgMod.HwOffloadEnabled)

	_, err := ApiHooks.NetIPsecConfigSet(&cfgMod)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Config update[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPsecTunnelsAll - Get all IPsec tunnels
func ConfigGetIPsecTunnelsAll(params operations.GetConfigIpsecTunnelsAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tunnels, err := ApiHooks.NetIPsecTunnelGetAll()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get tunnels[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get tunnels[OK]: count=%d\n", len(tunnels))

	var result []*models.IPsecTunnel
	for _, t := range tunnels {
		tunnel := &models.IPsecTunnel{
			Name:           t.Name,
			LocalIP:        t.LocalIP,
			RemoteIP:       t.RemoteIP,
			AuthMode:       t.AuthMode,
			LocalID:        t.LocalID,
			RemoteID:       t.RemoteID,
			CertName:       t.CertName,
			CaCertName:     t.CACertName,
			IkeVersion:     t.IKEVersion,
			IkeEncryption:  t.IKEEncryption,
			IkeIntegrity:   t.IKEIntegrity,
			IkeDhGroup:     t.IKEDHGroup,
			IkeLifetime:    int64(t.IKELifetime),
			EspEncryption:  t.ESPEncryption,
			EspIntegrity:   t.ESPIntegrity,
			EspDhGroup:     t.ESPDHGroup,
			EspLifetime:    int64(t.ESPLifetime),
			Mark:           t.Mark,
			TunnelMode:     t.TunnelMode,
			InstallPolicy:  t.InstallPolicy,
			Compress:       t.Compress,
			Mobike:         t.Mobike,
			Rekey:          t.Rekey,
			Reauth:         t.Reauth,
			Auto:           t.Auto,
			CompatFallback: t.CompatFallback,
			State:          t.State,
			BytesIn:        t.BytesIn,
			BytesOut:       t.BytesOut,
			PacketsIn:      t.PacketsIn,
			PacketsOut:     t.PacketsOut,
			SasInstalled:   int64(t.SAsInstalled),
		}

		// Selector
		tunnel.Selector = &models.IPsecSelector{
			SrcCidr:  t.Selector.SrcCIDR,
			DstCidr:  t.Selector.DstCIDR,
			Protocol: t.Selector.Protocol,
			SrcPort:  t.Selector.SrcPort,
			DstPort:  t.Selector.DstPort,
		}

		// DPD
		action := t.DPD.Action
		delay := t.DPD.Delay
		timeout := t.DPD.Timeout
		tunnel.Dpd = &models.IPsecDPD{
			Action:  &action,
			Delay:   &delay,
			Timeout: &timeout,
		}

		result = append(result, tunnel)
	}

	return operations.NewGetConfigIpsecTunnelsAllOK().WithPayload(&operations.GetConfigIpsecTunnelsAllOKBody{
		IpsecTunnelAttr: result,
	})
}

// ConfigPostIPsecTunnels - Create an IPsec tunnel
func ConfigPostIPsecTunnels(params operations.PostConfigIpsecTunnelsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tunnelMod := cmn.IPsecTunnelMod{
		Name:           derefString(params.Attr.Name),
		LocalIP:        derefString(params.Attr.LocalIP),
		RemoteIP:       derefString(params.Attr.RemoteIP),
		AuthMode:       derefString(params.Attr.AuthMode),
		PSK:            params.Attr.Psk,
		LocalID:        params.Attr.LocalID,
		RemoteID:       params.Attr.RemoteID,
		CertName:       params.Attr.CertName,
		CACertName:     params.Attr.CaCertName,
		IKEVersion:     derefString(params.Attr.IkeVersion),
		IKEEncryption:  derefString(params.Attr.IkeEncryption),
		IKEIntegrity:   derefString(params.Attr.IkeIntegrity),
		IKEDHGroup:     derefString(params.Attr.IkeDhGroup),
		IKELifetime:    derefUint32Ipsec(params.Attr.IkeLifetime),
		ESPEncryption:  derefString(params.Attr.EspEncryption),
		ESPIntegrity:   derefString(params.Attr.EspIntegrity),
		ESPDHGroup:     params.Attr.EspDhGroup,
		ESPLifetime:    derefUint32Ipsec(params.Attr.EspLifetime),
		Mark:           derefUint32Ipsec(params.Attr.Mark),
		TunnelMode:     derefString(params.Attr.TunnelMode),
		InstallPolicy:  derefBoolDefaultTrue(params.Attr.InstallPolicy),
		Compress:       derefBool(params.Attr.Compress),
		Mobike:         derefBool(params.Attr.Mobike),
		Rekey:          derefBoolDefaultTrue(params.Attr.Rekey),
		Reauth:         derefBool(params.Attr.Reauth),
		Auto:           derefString(params.Attr.Auto),
		CompatFallback: derefBool(params.Attr.CompatFallback),
	}

	// Selector
	if params.Attr.Selector != nil {
		tunnelMod.Selector = cmn.IPsecSelector{
			SrcCIDR:  params.Attr.Selector.SrcCidr,
			DstCIDR:  params.Attr.Selector.DstCidr,
			Protocol: params.Attr.Selector.Protocol,
			SrcPort:  params.Attr.Selector.SrcPort,
			DstPort:  params.Attr.Selector.DstPort,
		}
	}

	// DPD
	if params.Attr.Dpd != nil {
		tunnelMod.DPD = cmn.IPsecDPD{
			Action:  derefString(params.Attr.Dpd.Action),
			Delay:   derefUint32Ipsec(params.Attr.Dpd.Delay),
			Timeout: derefUint32Ipsec(params.Attr.Dpd.Timeout),
		}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel create: %s (%s <-> %s, auth=%s)\n",
		tunnelMod.Name, tunnelMod.LocalIP, tunnelMod.RemoteIP, tunnelMod.AuthMode)

	_, err := ApiHooks.NetIPsecTunnelAdd(&tunnelMod)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel add[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel add[OK]: %s\n", tunnelMod.Name)
	return operations.NewPostConfigIpsecTunnelsNoContent()
}

// ConfigPutIPsecTunnelsName - Update an IPsec tunnel in place
func ConfigPutIPsecTunnelsName(params operations.PutConfigIpsecTunnelsNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tunnelMod := cmn.IPsecTunnelMod{
		Name:           params.Name, // path name wins over body name
		LocalIP:        derefString(params.Attr.LocalIP),
		RemoteIP:       derefString(params.Attr.RemoteIP),
		AuthMode:       derefString(params.Attr.AuthMode),
		PSK:            params.Attr.Psk,
		LocalID:        params.Attr.LocalID,
		RemoteID:       params.Attr.RemoteID,
		CertName:       params.Attr.CertName,
		CACertName:     params.Attr.CaCertName,
		IKEVersion:     derefString(params.Attr.IkeVersion),
		IKEEncryption:  derefString(params.Attr.IkeEncryption),
		IKEIntegrity:   derefString(params.Attr.IkeIntegrity),
		IKEDHGroup:     derefString(params.Attr.IkeDhGroup),
		IKELifetime:    derefUint32Ipsec(params.Attr.IkeLifetime),
		ESPEncryption:  derefString(params.Attr.EspEncryption),
		ESPIntegrity:   derefString(params.Attr.EspIntegrity),
		ESPDHGroup:     params.Attr.EspDhGroup,
		ESPLifetime:    derefUint32Ipsec(params.Attr.EspLifetime),
		Mark:           derefUint32Ipsec(params.Attr.Mark),
		TunnelMode:     derefString(params.Attr.TunnelMode),
		InstallPolicy:  derefBoolDefaultTrue(params.Attr.InstallPolicy),
		Compress:       derefBool(params.Attr.Compress),
		Mobike:         derefBool(params.Attr.Mobike),
		Rekey:          derefBoolDefaultTrue(params.Attr.Rekey),
		Reauth:         derefBool(params.Attr.Reauth),
		Auto:           derefString(params.Attr.Auto),
		CompatFallback: derefBool(params.Attr.CompatFallback),
	}

	// Selector
	if params.Attr.Selector != nil {
		tunnelMod.Selector = cmn.IPsecSelector{
			SrcCIDR:  params.Attr.Selector.SrcCidr,
			DstCIDR:  params.Attr.Selector.DstCidr,
			Protocol: params.Attr.Selector.Protocol,
			SrcPort:  params.Attr.Selector.SrcPort,
			DstPort:  params.Attr.Selector.DstPort,
		}
	}

	// DPD
	if params.Attr.Dpd != nil {
		tunnelMod.DPD = cmn.IPsecDPD{
			Action:  derefString(params.Attr.Dpd.Action),
			Delay:   derefUint32Ipsec(params.Attr.Dpd.Delay),
			Timeout: derefUint32Ipsec(params.Attr.Dpd.Timeout),
		}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel update: %s (%s <-> %s, auth=%s)\n",
		tunnelMod.Name, tunnelMod.LocalIP, tunnelMod.RemoteIP, tunnelMod.AuthMode)

	_, err := ApiHooks.NetIPsecTunnelUpdate(&tunnelMod)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel update[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel update[OK]: %s\n", tunnelMod.Name)
	return operations.NewPutConfigIpsecTunnelsNameNoContent()
}

// ConfigPostIPsecTunnelsNameAction - Initiate/terminate/restart a tunnel connection
func ConfigPostIPsecTunnelsNameAction(params operations.PostConfigIpsecTunnelsNameActionParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	action := derefString(params.Attr.Action)
	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel %s action: %s\n", params.Name, action)

	_, err := ApiHooks.NetIPsecTunnelAction(params.Name, action)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel action[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel action[OK]: %s %s\n", params.Name, action)
	return operations.NewPostConfigIpsecTunnelsNameActionNoContent()
}

// ConfigGetIPsecTunnelsName - Get specific IPsec tunnel
func ConfigGetIPsecTunnelsName(params operations.GetConfigIpsecTunnelsNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tunnel, err := ApiHooks.NetIPsecTunnelGet(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get tunnel %s[NOK]: %v\n", params.Name, err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get tunnel %s[OK]: state=%s\n", params.Name, tunnel.State)

	result := &models.IPsecTunnel{
		Name:           tunnel.Name,
		LocalIP:        tunnel.LocalIP,
		RemoteIP:       tunnel.RemoteIP,
		AuthMode:       tunnel.AuthMode,
		LocalID:        tunnel.LocalID,
		RemoteID:       tunnel.RemoteID,
		CertName:       tunnel.CertName,
		CaCertName:     tunnel.CACertName,
		IkeVersion:     tunnel.IKEVersion,
		IkeEncryption:  tunnel.IKEEncryption,
		IkeIntegrity:   tunnel.IKEIntegrity,
		IkeDhGroup:     tunnel.IKEDHGroup,
		IkeLifetime:    int64(tunnel.IKELifetime),
		EspEncryption:  tunnel.ESPEncryption,
		EspIntegrity:   tunnel.ESPIntegrity,
		EspDhGroup:     tunnel.ESPDHGroup,
		EspLifetime:    int64(tunnel.ESPLifetime),
		Mark:           tunnel.Mark,
		TunnelMode:     tunnel.TunnelMode,
		InstallPolicy:  tunnel.InstallPolicy,
		Compress:       tunnel.Compress,
		Mobike:         tunnel.Mobike,
		Rekey:          tunnel.Rekey,
		Reauth:         tunnel.Reauth,
		Auto:           tunnel.Auto,
		CompatFallback: tunnel.CompatFallback,
		State:          tunnel.State,
		BytesIn:        tunnel.BytesIn,
		BytesOut:       tunnel.BytesOut,
		PacketsIn:      tunnel.PacketsIn,
		PacketsOut:     tunnel.PacketsOut,
		SasInstalled:   int64(tunnel.SAsInstalled),
	}

	// Selector
	result.Selector = &models.IPsecSelector{
		SrcCidr:  tunnel.Selector.SrcCIDR,
		DstCidr:  tunnel.Selector.DstCIDR,
		Protocol: tunnel.Selector.Protocol,
		SrcPort:  tunnel.Selector.SrcPort,
		DstPort:  tunnel.Selector.DstPort,
	}

	// DPD
	action := tunnel.DPD.Action
	delay := tunnel.DPD.Delay
	timeout := tunnel.DPD.Timeout
	result.Dpd = &models.IPsecDPD{
		Action:  &action,
		Delay:   &delay,
		Timeout: &timeout,
	}

	return operations.NewGetConfigIpsecTunnelsNameOK().WithPayload(result)
}

// ConfigGetIPsecTunnelsNamePeerconfig - Generate remote-peer strongSwan configuration
func ConfigGetIPsecTunnelsNamePeerconfig(params operations.GetConfigIpsecTunnelsNamePeerconfigParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	peerCfg, err := ApiHooks.NetIPsecTunnelPeerConfig(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Peer config %s[NOK]: %v\n", params.Name, err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Peer config generated for tunnel %s\n", params.Name)

	result := &models.IPsecPeerConfig{
		TunnelName:   peerCfg.TunnelName,
		IpsecConf:    peerCfg.IPsecConf,
		IpsecSecrets: peerCfg.IPsecSecrets,
		Notes:        peerCfg.Notes,
	}

	return operations.NewGetConfigIpsecTunnelsNamePeerconfigOK().WithPayload(result)
}

// ConfigDeleteIPsecTunnelsName - Delete an IPsec tunnel
func ConfigDeleteIPsecTunnelsName(params operations.DeleteConfigIpsecTunnelsNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogInfo, "[IPsec] Tunnel delete: %s\n", params.Name)

	_, err := ApiHooks.NetIPsecTunnelDel(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Tunnel delete[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPsecSasAll - Get all Security Associations
func ConfigGetIPsecSasAll(params operations.GetConfigIpsecSasAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	sas, err := ApiHooks.NetIPsecSAGetAll()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get SAs[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get SAs[OK]: count=%d\n", len(sas))

	var result []*models.IPsecSA
	for _, sa := range sas {
		result = append(result, &models.IPsecSA{
			Spi:            sa.SPI,
			TunnelName:     sa.TunnelName,
			Direction:      sa.Direction,
			LocalIP:        sa.LocalIP,
			RemoteIP:       sa.RemoteIP,
			Encryption:     sa.Encryption,
			Integrity:      sa.Integrity,
			State:          sa.State,
			BytesIn:        sa.BytesIn,
			BytesOut:       sa.BytesOut,
			PacketsIn:      sa.PacketsIn,
			PacketsOut:     sa.PacketsOut,
			SequenceNumber: sa.SequenceNumber,
			ReplayWindow:   sa.ReplayWindow,
		})
	}

	return operations.NewGetConfigIpsecSasAllOK().WithPayload(&operations.GetConfigIpsecSasAllOKBody{
		IpsecSaAttr: result,
	})
}

// ConfigGetIPsecStats - Get IPsec statistics
func ConfigGetIPsecStats(params operations.GetConfigIpsecStatsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	stats, err := ApiHooks.NetIPsecStatsGet()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get stats[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get stats[OK]: tunnels=%d, SAs=%d\n", stats.TotalTunnels, stats.TotalSAs)

	result := &models.IPsecStats{
		TotalTunnels:    int64(stats.TotalTunnels),
		TunnelsUp:       int64(stats.TunnelsUp),
		TunnelsDown:     int64(stats.TunnelsDown),
		TotalSas:        int64(stats.TotalSAs),
		TotalBytesIn:    stats.TotalBytesIn,
		TotalBytesOut:   stats.TotalBytesOut,
		TotalPacketsIn:  stats.TotalPacketsIn,
		TotalPacketsOut: stats.TotalPacketsOut,
		EncryptErrors:   stats.EncryptErrors,
		DecryptErrors:   stats.DecryptErrors,
		AuthErrors:      stats.AuthErrors,
		ReplayErrors:    stats.ReplayErrors,
		SeqOverflows:    stats.SeqOverflows,
	}

	return operations.NewGetConfigIpsecStatsOK().WithPayload(result)
}

// ConfigDeleteIPsecStats - Reset IPsec statistics
func ConfigDeleteIPsecStats(params operations.DeleteConfigIpsecStatsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogInfo, "[IPsec] Reset statistics\n")

	_, err := ApiHooks.NetIPsecStatsReset()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Reset stats[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPsecCertificatesAll - Get all certificates
func ConfigGetIPsecCertificatesAll(params operations.GetConfigIpsecCertificatesAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	certs, err := ApiHooks.NetIPsecCertificateGetAll()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get certificates[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get certificates[OK]: count=%d\n", len(certs))

	var result []*models.IPsecCertificate
	for _, cert := range certs {
		result = append(result, &models.IPsecCertificate{
			Name:        cert.Name,
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			Serial:      cert.Serial,
			San:         cert.SAN,
			KeyUsage:    cert.KeyUsage,
			Description: cert.Description,
		})
	}

	return operations.NewGetConfigIpsecCertificatesAllOK().WithPayload(&operations.GetConfigIpsecCertificatesAllOKBody{
		IpsecCertificateAttr: result,
	})
}

// ConfigPostIPsecCertificates - Upload a certificate
func ConfigPostIPsecCertificates(params operations.PostConfigIpsecCertificatesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	certMod := cmn.IPsecCertificateMod{
		Name:           derefString(params.Attr.Name),
		CertificatePEM: derefString(params.Attr.Certificate),
		PrivateKeyPEM:  derefString(params.Attr.PrivateKey),
		Passphrase:     params.Attr.Passphrase,
		Description:    params.Attr.Description,
	}

	tk.LogIt(tk.LogInfo, "[IPsec] Certificate upload: %s\n", certMod.Name)

	_, err := ApiHooks.NetIPsecCertificateAdd(&certMod)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Certificate add[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Get the installed certificate to return details
	cert, _ := ApiHooks.NetIPsecCertificateGet(certMod.Name)
	if cert != nil {
		result := &models.IPsecCertificate{
			Name:        cert.Name,
			Subject:     cert.Subject,
			Issuer:      cert.Issuer,
			Serial:      cert.Serial,
			San:         cert.SAN,
			KeyUsage:    cert.KeyUsage,
			Description: cert.Description,
		}
		return operations.NewPostConfigIpsecCertificatesCreated().WithPayload(result)
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPsecCertificatesName - Get certificate details
func ConfigGetIPsecCertificatesName(params operations.GetConfigIpsecCertificatesNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	cert, err := ApiHooks.NetIPsecCertificateGet(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get certificate %s[NOK]: %v\n", params.Name, err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get certificate %s[OK]: subject=%s\n", params.Name, cert.Subject)

	result := &models.IPsecCertificate{
		Name:        cert.Name,
		Subject:     cert.Subject,
		Issuer:      cert.Issuer,
		Serial:      cert.Serial,
		San:         cert.SAN,
		KeyUsage:    cert.KeyUsage,
		Description: cert.Description,
	}

	return operations.NewGetConfigIpsecCertificatesNameOK().WithPayload(result)
}

// ConfigDeleteIPsecCertificatesName - Delete a certificate
func ConfigDeleteIPsecCertificatesName(params operations.DeleteConfigIpsecCertificatesNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogInfo, "[IPsec] Certificate delete: %s\n", params.Name)

	_, err := ApiHooks.NetIPsecCertificateDel(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Certificate delete[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigPostIPsecCertificatesValidate - Validate certificate
func ConfigPostIPsecCertificatesValidate(params operations.PostConfigIpsecCertificatesValidateParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogDebug, "[IPsec] Certificate validation requested\n")

	validation, err := ApiHooks.NetIPsecCertificateValidate(
		derefString(params.Attr.Certificate),
		derefString(params.Attr.PrivateKey),
		params.Attr.Passphrase,
	)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Certificate validation[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	result := &models.IPsecCertValidation{
		Valid:        validation.Valid,
		Errors:       validation.Errors,
		Warnings:     validation.Warnings,
		Subject:      validation.Subject,
		Issuer:       validation.Issuer,
		KeyAlgorithm: validation.KeyAlgorithm,
		KeySize:      int64(validation.KeySize),
	}

	return operations.NewPostConfigIpsecCertificatesValidateOK().WithPayload(result)
}

// ConfigGetIPsecCaCertificatesAll - Get all CA certificates
func ConfigGetIPsecCaCertificatesAll(params operations.GetConfigIpsecCaCertificatesAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	caCerts, err := ApiHooks.NetIPsecCACertificateGetAll()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get CA certificates[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get CA certificates[OK]: count=%d\n", len(caCerts))

	var result []*models.IPsecCACertificate
	for _, caCert := range caCerts {
		result = append(result, &models.IPsecCACertificate{
			Name:        caCert.Name,
			Subject:     caCert.Subject,
			Issuer:      caCert.Issuer,
			Serial:      caCert.Serial,
			Description: caCert.Description,
		})
	}

	return operations.NewGetConfigIpsecCaCertificatesAllOK().WithPayload(&operations.GetConfigIpsecCaCertificatesAllOKBody{
		IpsecCACertificateAttr: result,
	})
}

// ConfigPostIPsecCaCertificates - Upload a CA certificate
func ConfigPostIPsecCaCertificates(params operations.PostConfigIpsecCaCertificatesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	caCertMod := cmn.IPsecCACertificateMod{
		Name:           derefString(params.Attr.Name),
		CertificatePEM: derefString(params.Attr.Certificate),
		Description:    params.Attr.Description,
	}

	tk.LogIt(tk.LogInfo, "[IPsec] CA certificate upload: %s\n", caCertMod.Name)

	_, err := ApiHooks.NetIPsecCACertificateAdd(&caCertMod)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] CA certificate add[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Get the installed CA certificate to return details
	caCert, _ := ApiHooks.NetIPsecCACertificateGet(caCertMod.Name)
	if caCert != nil {
		result := &models.IPsecCACertificate{
			Name:        caCert.Name,
			Subject:     caCert.Subject,
			Issuer:      caCert.Issuer,
			Serial:      caCert.Serial,
			Description: caCert.Description,
		}
		return operations.NewPostConfigIpsecCaCertificatesCreated().WithPayload(result)
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPsecCaCertificatesName - Get CA certificate details
func ConfigGetIPsecCaCertificatesName(params operations.GetConfigIpsecCaCertificatesNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	caCert, err := ApiHooks.NetIPsecCACertificateGet(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] Get CA certificate %s[NOK]: %v\n", params.Name, err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogDebug, "[IPsec] Get CA certificate %s[OK]: subject=%s\n", params.Name, caCert.Subject)

	result := &models.IPsecCACertificate{
		Name:        caCert.Name,
		Subject:     caCert.Subject,
		Issuer:      caCert.Issuer,
		Serial:      caCert.Serial,
		Description: caCert.Description,
	}

	return operations.NewGetConfigIpsecCaCertificatesNameOK().WithPayload(result)
}

// ConfigDeleteIPsecCaCertificatesName - Delete a CA certificate
func ConfigDeleteIPsecCaCertificatesName(params operations.DeleteConfigIpsecCaCertificatesNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPsec %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogInfo, "[IPsec] CA certificate delete: %s\n", params.Name)

	_, err := ApiHooks.NetIPsecCACertificateDel(params.Name)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPsec] CA certificate delete[NOK]: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}
