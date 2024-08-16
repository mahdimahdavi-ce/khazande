package psql

import (
	"context"
	"fmt"
	"khazande/ent"
	"khazande/ent/vulnerability"
	"khazande/internal/types"
	"time"

	"github.com/google/uuid"
)

type Psql struct {
	PsqlClient *ent.Client
}

func (p *Psql) InsertVulnerabilities(piplineId uuid.UUID, vulnerabilitiesMap map[string][]*types.Vulnerability) {
	for _, vulnerabilities := range vulnerabilitiesMap {
		for _, vulnerability := range vulnerabilities {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			p.PsqlClient.Vulnerability.Create().
				SetName(vulnerability.Name).
				SetSummary(vulnerability.Summary).
				SetCVEID(vulnerability.CVEID).
				SetPublishedDate(vulnerability.PublishedDate).
				SetLastModified(vulnerability.LastModified).
				SetDescription(vulnerability.Description).
				SetNVDScore(vulnerability.NVDScore).
				SetCNAScore(vulnerability.CNAScore).
				SetAffectedVersions(vulnerability.AffectedVersions).
				SetPatchedVersions(vulnerability.PatchedVersions).
				SetSeverity(vulnerability.Severity).
				SetPiplineID(piplineId.String()).
				Save(ctx)

			cancel()
		}
	}
}

func (p *Psql) GetVulnerabilities(piplineId string) ([]*ent.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	vulnerabilities, err := p.PsqlClient.Vulnerability.Query().Where(vulnerability.PiplineID(piplineId)).All(ctx)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return vulnerabilities, nil
}
