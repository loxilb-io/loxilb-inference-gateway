package loxinlp

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
	opt "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
)

func pruneBootFrontendClientCAs() {
	rules, err := hooks.NetLbRuleGet()
	if err == nil {
		err = pruneFrontendClientCAs(opt.Opts.ConfigPath, rules)
	}
	if err != nil {
		tk.LogIt(tk.LogWarning, "nlp: prune frontend client CA files: %v\n", err)
	}
}

// Only the boot replay caller invokes this while REST writes are gated.
func pruneFrontendClientCAs(configPath string, rules []cmn.LbRuleMod) error {
	dir, err := filepath.Abs(filepath.Join(configPath, cmn.FrontendClientCADir))
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return &os.PathError{Op: "prune managed CA directory", Path: dir, Err: os.ErrInvalid}
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, rule := range rules {
		f := rule.Serv.MTLSFrontend
		if f == nil {
			continue
		}
		if f.ClientCAPath != "" {
			target, err := filepath.EvalSymlinks(f.ClientCAPath)
			if err == nil && filepath.Dir(target) == realDir {
				keep[filepath.Base(target)] = true
			}
			continue
		}
		if f.ClientCertMode != "required" && f.ClientCertMode != "optional" {
			continue
		}
		bundle, err := cmn.DecodeFrontendClientCA(f.ClientCACertData)
		if err != nil {
			return err
		}
		keep[cmn.FrontendClientCAFilename(bundle)] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var removeErrors []error
	for _, entry := range entries {
		name := entry.Name()
		stem, ok := strings.CutSuffix(name, ".pem")
		if !ok || len(stem) != 64 || strings.ToLower(stem) != stem || keep[name] || !entry.Type().IsRegular() {
			continue
		}
		if _, err := hex.DecodeString(stem); err != nil {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			removeErrors = append(removeErrors, err)
		}
	}
	return errors.Join(removeErrors...)
}
