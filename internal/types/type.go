package types

import "time"

type Vulnerability struct {
	Name               string   `json:"name"`
	Summary            string   `json:"summary"`
	CVEID              string   `json:"CVEID"`
	PublishedDate      string   `json:"publishDate"`
	LastModified       string   `json:"lastModified"`
	Description        string   `json:"description"`
	VulnerableVersions []string `json:"vulnerableVersions"`
	NVDScore           string   `json:"NVDScore"`
	CNAScore           string   `json:"CNAScore"`
	AffectedVersions   string   `json:"affectedVersions"`
	PatchedVersions    string   `json:"patchedVersions"`
	Severity           string   `json:"severity"`
}

type GitHubVulnerabilityQueryResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []VulnerabilityNode `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
}

type VulnerabilityNode struct {
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
	Advisory struct {
		Summary     string       `json:"summary"`
		Description string       `json:"description"`
		Severity    string       `json:"severity"`
		Identifiers []Identifier `json:"identifiers"`
		PublishedAt time.Time    `json:"publishedAt"`
		CVSS        struct {
			Score string `json:"score"`
		} `json:"cvss"`
	} `json:"advisory"`
	VulnerableVersionRange string `json:"vulnerableVersionRange"`
	FirstPatchedVersion    struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
