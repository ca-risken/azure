package prowler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ca-risken/azure/pkg/common"
	"github.com/ca-risken/common/pkg/grpc_client"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

type prowlerFinding struct {
	Metadata     prowlerMetadata    `json:"metadata"`
	FindingInfo  prowlerFindingInfo `json:"finding_info"`
	Resources    []prowlerResource  `json:"resources"`
	Remediation  prowlerRemediation `json:"remediation"`
	StatusDetail string             `json:"status_detail"`
	Severity     string             `json:"severity"`
	StatusCode   string             `json:"status_code"`
	Tags         *[]string          `json:"tags,omitempty"`
}

type prowlerMetadata struct {
	EventCode string `json:"event_code"`
}

type prowlerFindingInfo struct {
	Desc  string `json:"desc"`
	Title string `json:"title"`
}

type prowlerResource struct {
	Region string       `json:"region"`
	Name   string       `json:"name"`
	UID    string       `json:"uid"`
	Type   string       `json:"type"`
	Group  prowlerGroup `json:"group"`
}

type prowlerGroup struct {
	Name string `json:"name"`
}

type prowlerRemediation struct {
	Desc       string   `json:"desc"`
	References []string `json:"references"`
}

func (s *SqsHandler) makeFindingBatchForUpsert(ctx context.Context, projectID uint32, subscriptionID string, prowlerFindings *[]prowlerFinding) error {
	var resourceBatch []*finding.ResourceBatchForUpsert
	var findingBatch []*finding.FindingBatchForUpsert
	for _, pf := range *prowlerFindings {
		resourceUID := s.getResourceUID(ctx, pf)
		if resourceUID == "" {
			s.logger.Warnf(ctx, "Resource UID is empty, project_id=%d, subscription_id=%s, pf=%+v", projectID, subscriptionID, pf)
			continue
		}
		groupName := s.getResourceGroupName(ctx, pf)
		score := pf.getScore(groupName)
		if score == 0.0 {
			resourceBatch = append(resourceBatch, makeResource(projectID, resourceUID, subscriptionID, groupName))
		}
		f, err := s.makeFinding(ctx, projectID, subscriptionID, resourceUID, groupName, score, &pf)
		if err != nil {
			return err
		}
		if f != nil {
			findingBatch = append(findingBatch, f)
		}
	}
	return s.putFindings(ctx, projectID, resourceBatch, findingBatch)
}

func (s *SqsHandler) putFindings(ctx context.Context, projectID uint32, resourceBatch []*finding.ResourceBatchForUpsert, findingBatch []*finding.FindingBatchForUpsert) error {
	if len(resourceBatch) > 0 {
		err := grpc_client.PutResourceBatch(ctx, s.findingClient, projectID, resourceBatch)
		if err != nil {
			return err
		}
	}
	if len(findingBatch) > 0 {
		err := grpc_client.PutFindingBatch(ctx, s.findingClient, projectID, findingBatch)
		if err != nil {
			return err
		}
	}
	return nil
}

func makeResource(projectID uint32, resourceUID, subscriptionID, groupName string) *finding.ResourceBatchForUpsert {
	// PutResource
	r := &finding.ResourceBatchForUpsert{
		Resource: &finding.ResourceForUpsert{
			ResourceName: resourceUID,
			ProjectId:    projectID,
		},
	}
	tags := []*finding.ResourceTagForBatch{
		{Tag: common.TagAzure},
		{Tag: subscriptionID},
		{Tag: strings.ToLower(groupName)},
	}
	r.Tag = tags
	return r
}

func (s *SqsHandler) makeFinding(ctx context.Context, projectID uint32, subscriptionID, resourceUID, groupName string, score float32, pf *prowlerFinding) (*finding.FindingBatchForUpsert, error) {
	region := s.getResourceRegion(ctx, *pf)
	buf, err := json.Marshal(pf)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to marshal user data, project_id=%d, resource=%s, err=%+v", projectID, resourceUID, err)
		return nil, err
	}
	dataSourceID := generateDataSourceID(subscriptionID, pf.Metadata.EventCode, region, resourceUID)
	f := &finding.FindingBatchForUpsert{
		Finding: &finding.FindingForUpsert{
			Description:      shorten(pf.StatusDetail, 200),
			DataSource:       message.AzureProwlerDataSource,
			DataSourceId:     dataSourceID,
			ResourceName:     resourceUID,
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	}
	tags := []*finding.FindingTagForBatch{
		{Tag: common.TagAzure},
		{Tag: common.TagProwler},
		{Tag: strings.ToLower(groupName)},
		{Tag: subscriptionID},
		{Tag: pf.Metadata.EventCode},
	}
	f.Tag = tags
	f.Recommend = s.getRecommend(ctx, pf, groupName)

	return f, nil
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func (s *SqsHandler) getRecommend(ctx context.Context, pf *prowlerFinding, resourceGroup string) *finding.RecommendForBatch {
	event := pf.Metadata.EventCode
	pluginMetadata := pluginMap[fmt.Sprintf("%s/%s", resourceGroup, event)]
	r := pluginMetadata.Recommend
	if r.Risk == "" && r.Recommendation == "" {
		s.logger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", event)
		return nil
	}
	return &finding.RecommendForBatch{
		Type:           event,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}
}

func generateDataSourceID(subscriptionID, event, region, resource string) string {
	hash := sha256.Sum256([]byte(subscriptionID + event + region + resource))
	return hex.EncodeToString(hash[:])
}

func (f *prowlerFinding) getScore(resourceGroup string) float32 {
	cat := fmt.Sprintf("%s/%s", resourceGroup, f.Metadata.EventCode)
	switch strings.ToUpper(f.StatusCode) {
	case resultPASS:
		return 0.0
	default:
		// FAIL
		if plugin, ok := pluginMap[cat]; ok {
			return plugin.Score
		}
		return 0.3
	}
}

func (s *SqsHandler) getResourceUID(ctx context.Context, f prowlerFinding) string {
	// Resourceが複数あるケースが見つからないため、調査のためにログを出力
	// 最初のResourceを返す
	if len(f.Resources) > 1 {
		s.logger.Warnf(ctx, "Multiple resources are found. %v", f.Resources)
	}
	if len(f.Resources) == 0 {
		return ""
	}
	// serviceがMonitorの場合にUIDが空になるケースがある
	// 他のMonitorと合わせてUIDをMonitorにする
	ret := f.Resources[0].UID
	if ret == "" {
		ret = f.Resources[0].Type
	}

	return ret
}

func (s *SqsHandler) getResourceRegion(ctx context.Context, f prowlerFinding) string {
	// Resourceが複数あるケースが見つからないため、調査のためにログを出力
	// 最初のResourceを返す
	if len(f.Resources) > 1 {
		s.logger.Warnf(ctx, "Multiple resources are found. %v", f.Resources)
	}
	if len(f.Resources) == 0 {
		return ""
	}
	return f.Resources[0].Region
}

func (s *SqsHandler) getResourceGroupName(ctx context.Context, f prowlerFinding) string {
	// Resourceが複数あるケースが見つからないため、調査のためにログを出力
	// 最初のResourceを返す
	if len(f.Resources) > 1 {
		s.logger.Warnf(ctx, "Multiple resources are found. %v", f.Resources)
	}
	if len(f.Resources) == 0 {
		return ""
	}
	return f.Resources[0].Group.Name
}
