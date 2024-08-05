package report

import (
	"encoding/json"
	"errors"
	"os"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type TrivyParser struct{}

func parseTrivyReport(file string) (*trivyTypes.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var msr trivyTypes.Report
	if err = json.Unmarshal(data, &msr); err != nil {
		return nil, &ErrorUnsupported{err}
	}
	return &msr, nil
}

func NewTrivyParser() *TrivyParser {
	return &TrivyParser{}
}

func (t *TrivyParser) Parse(file string) (*unversioned.UpdateManifest, error) {
	report, err := parseTrivyReport(file)
	if err != nil {
		return nil, err
	}

	// Precondition check
	osResult := trivyTypes.Result{}
	pkgResult := trivyTypes.Result{}
	for i := range report.Results {
		r := &report.Results[i]
		if r.Class == trivyTypes.ClassOSPkg {
			if osResult.Class != "" {
				return nil, errors.New("unexpected multiple results for os-pkgs")
			}
			osResult = *r
		} else if r.Class == trivyTypes.ClassLangPkg {
			if pkgResult.Class != "" {
				return nil, errors.New("unexpected multiple results for lang-pkgs")
			}
			pkgResult = *r
		}
	}
	if osResult.Class == "" {
		return nil, errors.New("no scanning results for os-pkgs found")
	}

	updates := unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    string(report.Metadata.OS.Family),
				Version: report.Metadata.OS.Name,
			},
			Config: unversioned.Config{
				Arch: report.Metadata.ImageConfig.Architecture,
			},
		},
	}

	for i := range osResult.Vulnerabilities {
		vuln := &osResult.Vulnerabilities[i]
		if vuln.FixedVersion != "" {
			updates.OSUpdates = append(updates.OSUpdates, unversioned.UpdatePackage{
				Name:             vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				VulnerabilityID:  vuln.VulnerabilityID,
			})
		}
	}

	for i := range pkgResult.Vulnerabilities {
		vuln := &pkgResult.Vulnerabilities[i]
		if vuln.FixedVersion != "" {
			updates.LanguageUpdates = append(updates.LanguageUpdates, unversioned.UpdatePackage{
				Name:             vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				VulnerabilityID:  vuln.VulnerabilityID,
			})
		}
	}

	return &updates, nil
}
