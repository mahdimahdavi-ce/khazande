package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	advisorModule "khazande/internal/advisor"
	"khazande/internal/types"
	envsModule "khazande/pkg/envs"
	"log"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jedib0t/go-pretty/table"
	"go.uber.org/zap"
)

type Handler struct {
	Advisor *advisorModule.Advisor
}

type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func Initial(envs *envsModule.Envs, logger *zap.Logger) *Handler {
	return &Handler{
		Advisor: &advisorModule.Advisor{
			Logger: logger,
			Envs:   envs,
		},
	}
}

func (h *Handler) VulnerabilityHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		codeType := c.Params("type")

		packages := make(map[string]string)
		var ecosystem string

		switch codeType {
		case "Go":
			packages = extractGoPackages(string(c.Body()))
			ecosystem = "GO"
		case "Javascript":
			packages = extractJavascriptPackages(c.Body())
			ecosystem = "npm"
		case "Python":
			packages = extractPythonPackages(string(c.Body()))
			ecosystem = "pip"
		}

		vulerabilities := h.Advisor.FetchVulnerabilitiesFromGithub(packages, ecosystem)

		if len(vulerabilities) > 0 {
			result := renderTableResult(vulerabilities)
			return c.Status(200).SendString(result)
		} else {
			return c.Status(400).SendString("No vulnerabilities found!")
		}

	}
}

func extractGoPackages(gomod string) map[string]string {
	// Regular expression to match package names and versions
	re := regexp.MustCompile(`\s*([^ \n\r\t]+)\s+v([0-9]+\.[0-9]+\.[0-9]+)`)

	matches := re.FindAllStringSubmatch(gomod, -1)

	packages := make(map[string]string)

	for _, match := range matches {
		if len(match) == 3 {
			packages[match[1]] = match[2]
		}
	}

	return packages
}

func extractJavascriptPackages(packagejson []byte) map[string]string {
	// Parse the JSON
	var pkg PackageJSON
	err := json.Unmarshal(packagejson, &pkg)
	if err != nil {
		log.Fatalf("Error parsing package.json: %v", err)
	}

	packages := make(map[string]string)

	for name, version := range pkg.Dependencies {
		packages[name] = version
	}

	for name, version := range pkg.DevDependencies {
		packages[name] = version
	}

	fmt.Println(packages)
	return packages
}

func extractPythonPackages(requirmentstxt string) map[string]string {
	packages := make(map[string]string)

	regex := regexp.MustCompile(`(?P<package>[a-zA-Z0-9_-]+)(?P<operator>[<>=!~]*)\s*(?P<version>[0-9.*]*)`)
	lines := strings.Split(requirmentstxt, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Find matches
		matches := regex.FindStringSubmatch(line)

		if len(matches) > 0 {
			pkgName := matches[1]
			version := matches[3]

			packages[pkgName] = version
		}
	}
	fmt.Println(packages)

	return packages
}

func renderTableResult(vulerabilities map[string][]*types.Vulnerability) string {
	var buffer bytes.Buffer
	t := table.NewWriter()
	t.SetOutputMirror(&buffer)
	t.AppendHeader(table.Row{"#", "Package", "Vulnerability", "Severity", "Affected Versions", "Fixed Version", "Title"})
	style := table.Style{
		Box: table.BoxStyle{
			BottomLeft:       "+",
			BottomRight:      "+",
			BottomSeparator:  "-",
			Left:             "|",
			LeftSeparator:    "+",
			Right:            "|",
			RightSeparator:   "+",
			MiddleHorizontal: "-",
			MiddleSeparator:  "+",
			MiddleVertical:   "|",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			TopLeft:          "+",
			TopRight:         "+",
			TopSeparator:     "-",
			UnfinishedRow:    "+",
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateHeader:  true,
			SeparateRows:    true,
			SeparateFooter:  true,
		},
	}

	t.SetStyle(style)
	count := 1

	for pkg, packageVulnerabilities := range vulerabilities {
		for _, vulnerability := range packageVulnerabilities {
			var title string
			words := strings.Fields(vulnerability.Summary)
			if len(words) < 6 {
				title = vulnerability.Summary
			} else {
				title = fmt.Sprintf("%s %s %s %s %s %s ...", words[0], words[1], words[2], words[3], words[4], words[5])
			}
			t.AppendRow([]interface{}{count, pkg, vulnerability.CVEID, vulnerability.Severity, vulnerability.AffectedVersions, vulnerability.PatchedVersions, title})
			count += 1
		}
	}
	t.AppendFooter(table.Row{"", "", "Total", count})
	t.Render()

	return buffer.String()
}
