package handlers

import (
	"bytes"
	"fmt"
	advisorModule "khazande/internal/advisor"
	"khazande/internal/types"
	envsModule "khazande/pkg/envs"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jedib0t/go-pretty/table"
	"go.uber.org/zap"
)

type Handler struct {
	Advisor *advisorModule.Advisor
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
		// Regular expression to match package names and versions
		re := regexp.MustCompile(`\s*([^ \n\r\t]+)\s+v([0-9]+\.[0-9]+\.[0-9]+)`)

		matches := re.FindAllStringSubmatch(string(c.Body()), -1)

		packages := make(map[string]string)

		for _, match := range matches {
			if len(match) == 3 {
				packages[match[1]] = match[2]
			}
		}

		vulerabilities := h.Advisor.FetchVulnerabilitiesFromGithub(packages)

		result := renderTableResult(vulerabilities)

		return c.Status(200).SendString(result)
	}
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
	// t.SortBy([]table.SortBy{
	// 	{Name: "#", Mode: table.Asc},
	// 	{Name: "Package", Mode: table.Asc},
	// })
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
