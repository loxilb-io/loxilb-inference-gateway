package loxinet

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
)

func prepareFrontendMTLS(serv *cmn.LbServiceArg) error {
	f := serv.MTLSFrontend
	if f == nil || f.ClientCertMode == "" || f.ClientCertMode == "disabled" {
		return nil
	}
	if serv.Mode != cmn.LBModeFullProxy ||
		(serv.Security != cmn.LBServHTTPS && serv.Security != cmn.LBServE2EHTTPS) {
		return fmt.Errorf("frontend mTLS requires fullproxy with HTTPS or E2E HTTPS")
	}
	if err := f.Validate(); err != nil {
		return err
	}
	if err := validateLBFixedCString("client_crl_path", f.ClientCRLPath, 255); err != nil {
		return err
	}
	_, _, err := resolveFrontendClientCA(opts.Opts.ConfigPath, f)
	return err
}

// resolveFrontendClientCA validates the path handed to native TLS, without
// writing to disk. A non-nil bundle needs to be materialized by the datapath.
func resolveFrontendClientCA(configPath string, f *cmn.MTLSFrontendConfig) (string, []byte, error) {
	if f.ClientCAPath != "" {
		return f.ClientCAPath, nil, validateLBFixedCString("client_ca_path", f.ClientCAPath, 255)
	}
	bundle, err := cmn.DecodeFrontendClientCA(f.ClientCACertData)
	if err != nil {
		return "", nil, err
	}
	path, err := cmn.FrontendClientCAFile(configPath, bundle)
	if err != nil {
		return "", nil, fmt.Errorf("resolve inline client CA path: %w", err)
	}
	return path, bundle, validateLBFixedCString("inline client CA path", path, 255)
}

func frontendClientCAPath(configPath string, f *cmn.MTLSFrontendConfig) (string, error) {
	path, bundle, err := resolveFrontendClientCA(configPath, f)
	if err != nil || bundle == nil {
		return path, err
	}
	if err := installFrontendClientCA(path, bundle); err != nil {
		return "", err
	}
	return path, nil
}

func installFrontendClientCA(path string, bundle []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create frontend client CA directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect frontend client CA directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("frontend client CA directory must be a real directory: %s", dir)
	}
	// Only reuse an intact, regular managed file. A damaged file or symlink
	// can be replaced atomically by the original bundle from the rule.
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode().IsRegular() && info.Size() == int64(len(bundle)):
		data, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(data, bundle) {
			return nil
		}
	case err != nil && !os.IsNotExist(err):
		return fmt.Errorf("inspect cached frontend client CA: %w", err)
	}
	file, err := os.CreateTemp(dir, ".ca-*")
	if err != nil {
		return fmt.Errorf("create frontend client CA file: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(bundle); err != nil {
		return fmt.Errorf("write frontend client CA file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync frontend client CA file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close frontend client CA file: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("install frontend client CA file: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open frontend client CA directory: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync frontend client CA directory: %w", err)
	}
	return nil
}
