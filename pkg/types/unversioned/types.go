package unversioned

type UpdateManifest struct {
	Metadata        Metadata       `json:"metadata"`
	OSUpdates       UpdatePackages `json:"updates"`
	LanguageUpdates UpdatePackages `json:"languageUpdates"`
}

type UpdatePackages []UpdatePackage

type Metadata struct {
	OS       OS       `json:"os"`
	Config   Config   `json:"config"`
	Language Language `json:"language"`
}

type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type Language struct {
	Type string `json:"type"`
}

type Config struct {
	Arch string `json:"arch"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}
