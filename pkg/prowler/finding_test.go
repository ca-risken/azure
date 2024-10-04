package prowler

import (
	"context"
	"reflect"
	"testing"

	"github.com/ca-risken/azure/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/finding"
)

func TestMakeResource(t *testing.T) {
	type args struct {
		projectID      uint32
		resourceUID    string
		subscriptionID string
		groupName      string
	}
	cases := []struct {
		name  string
		input args
		want  *finding.ResourceBatchForUpsert
	}{
		{
			name: "OK",
			input: args{
				projectID:      1,
				resourceUID:    "uid1",
				subscriptionID: "sub1",
				groupName:      "group1",
			},
			want: &finding.ResourceBatchForUpsert{
				Resource: &finding.ResourceForUpsert{
					ProjectId:    1,
					ResourceName: "uid1",
				},
				Tag: []*finding.ResourceTagForBatch{
					{Tag: common.TagAzure},
					{Tag: "sub1"},
					{Tag: "group1"},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := makeResource(c.input.projectID, c.input.resourceUID, c.input.subscriptionID, c.input.groupName)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestMakeFinding(t *testing.T) {
	ctx := context.Background()
	type args struct {
		projectID      uint32
		subscriptionID string
		resourceUID    string
		groupName      string
		score          float32
		pf             *prowlerFinding
	}
	cases := []struct {
		name    string
		input   args
		want    *finding.FindingBatchForUpsert
		wantErr bool
	}{
		{
			name: "OK",
			input: args{
				projectID:      1,
				subscriptionID: "sub1",
				resourceUID:    "uid1",
				groupName:      "group1",
				score:          0.8,
				pf: &prowlerFinding{
					Resources: []prowlerResource{
						{UID: "uid1"},
					},
					Metadata: prowlerMetadata{
						EventCode: "sqlserver_unrestricted_inbound_access",
					},
				},
			},
			want: &finding.FindingBatchForUpsert{
				Finding: &finding.FindingForUpsert{
					ProjectId:        1,
					ResourceName:     "uid1",
					OriginalScore:    0.8,
					OriginalMaxScore: 1.0,
					DataSourceId:     generateDataSourceID("sub1", "sqlserver_unrestricted_inbound_access", "", "uid1"),
					DataSource:       "azure:prowler",
					Data:             "{\"metadata\":{\"event_code\":\"sqlserver_unrestricted_inbound_access\"},\"finding_info\":{\"desc\":\"\",\"title\":\"\"},\"resources\":[{\"region\":\"\",\"name\":\"\",\"uid\":\"uid1\",\"type\":\"\",\"group\":{\"name\":\"\"}}],\"remediation\":{\"desc\":\"\",\"references\":null},\"status_detail\":\"\",\"severity\":\"\",\"status_code\":\"\"}",
				},
				Tag: []*finding.FindingTagForBatch{
					{Tag: common.TagAzure},
					{Tag: common.TagProwler},
					{Tag: "group1"},
					{Tag: "sub1"},
					{Tag: "sqlserver_unrestricted_inbound_access"},
				},
			},
			wantErr: false,
		},
	}
	for _, c := range cases {
		s := &SqsHandler{
			logger: logging.NewLogger(),
		}
		t.Run(c.name, func(t *testing.T) {
			got, err := s.makeFinding(ctx, c.input.projectID, c.input.subscriptionID, c.input.resourceUID, c.input.groupName, c.input.score, c.input.pf)
			if c.wantErr && err == nil {
				t.Fatalf("Expected error but got nil")
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	ctx := context.Background()
	type args struct {
		pf            *prowlerFinding
		resourceGroup string
	}
	cases := []struct {
		name  string
		input args
		want  *finding.RecommendForBatch
	}{
		{
			name: "OK",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "aks_cluster_rbac_enabled",
					},
				},
				resourceGroup: CategoryAKS,
			},
			want: &finding.RecommendForBatch{
				Risk:           "Kubernetes RBAC and AKS help you secure your cluster access and provide only the minimum required permissions to developers and operators.",
				Recommendation: "https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle",
				Type:           "aks_cluster_rbac_enabled",
			},
		},
		{
			name: "no recommend",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "not_found",
					},
				},
				resourceGroup: CategoryAKS,
			},
			want: nil,
		},
	}
	for _, c := range cases {
		s := &SqsHandler{
			logger: logging.NewLogger(),
		}
		t.Run(c.name, func(t *testing.T) {
			got := s.getRecommend(ctx, c.input.pf, c.input.resourceGroup)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
func TestGetScore(t *testing.T) {
	type args struct {
		pf            *prowlerFinding
		resourceGroup string
	}
	cases := []struct {
		name  string
		input args
		want  float32
	}{
		{
			name: "Critical",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "sqlserver_unrestricted_inbound_access",
					},
					Severity:   severityCritical,
					StatusCode: resultFAIL,
				},
				resourceGroup: CategorySQLServer,
			},
			want: 0.8,
		},
		{
			name: "High",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "aks_clusters_created_with_private_nodes",
					},
					Severity:   severityHigh,
					StatusCode: resultFAIL,
				},
				resourceGroup: CategoryAKS,
			},
			want: 0.6,
		},
		{
			name: "Medium",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "aks_cluster_rbac_enabled",
					},
					Severity:   severityMedium,
					StatusCode: resultFAIL,
				},
				resourceGroup: CategoryAKS,
			},
			want: 0.4,
		},
		{
			name: "Low",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "app_ensure_java_version_is_latest",
					},
					Severity:   severityLow,
					StatusCode: resultFAIL,
				},
				resourceGroup: CategoryApp,
			},
			want: 0.3,
		},
		{
			name: "PASS",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "app_ensure_java_version_is_latest",
					},
					Severity:   severityCritical,
					StatusCode: resultPASS,
				},
				resourceGroup: CategoryApp,
			},
			want: 0.0,
		},
		{
			name: "plugin has score",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "/entra_conditional_access_policy_require_mfa_for_management_api",
					},
					StatusCode: resultFAIL,
				},
				resourceGroup: CategoryEntra,
			},
			want: 0.3,
		},
		{
			name: "plugin not found",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "not_found",
					},
					StatusCode: resultFAIL,
				},
				resourceGroup: CategoryApp,
			},
			want: 0.3,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.input.pf.getScore(c.input.resourceGroup)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetTag(t *testing.T) {
	type args struct {
		pf            *prowlerFinding
		resourceGroup string
	}
	cases := []struct {
		name  string
		input args
		want  []string
	}{
		{
			name: "OK",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "aks_cluster_rbac_enabled",
					},
				},
				resourceGroup: CategoryAKS,
			},
			want: []string{"Microsoft.ContainerService/ManagedClusters"},
		},
		{
			name: "plugin not found",
			input: args{
				pf: &prowlerFinding{
					Metadata: prowlerMetadata{
						EventCode: "not_found",
					},
				},
				resourceGroup: CategoryApp,
			},
			want: []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.input.pf.getTag(c.input.resourceGroup)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetResourceUID(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		input prowlerFinding
		want  string
	}{
		{
			name: "OK one resource",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{UID: "uid1"},
				},
			},
			want: "uid1",
		},
		{
			name: "OK two resources",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{UID: "uid1"},
					{UID: "uid2"},
				},
			},
			want: "uid1",
		},
		{
			name: "noresource",
			input: prowlerFinding{
				Resources: []prowlerResource{},
			},
			want: "",
		},
		{
			name: "no resource uid",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{Type: "type1"},
				},
			},
			want: "type1",
		},
	}
	for _, c := range cases {
		s := &SqsHandler{
			logger: logging.NewLogger(),
		}
		t.Run(c.name, func(t *testing.T) {
			got := s.getResourceUID(ctx, c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetResourceRegion(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		input prowlerFinding
		want  string
	}{
		{
			name: "OK one region",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{Region: "region1"},
				},
			},
			want: "region1",
		},
		{
			name: "OK two regions",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{Region: "region1"},
					{Region: "region2"},
				},
			},
			want: "region1",
		},
		{
			name: "no region",
			input: prowlerFinding{
				Resources: []prowlerResource{},
			},
			want: "",
		},
	}
	for _, c := range cases {
		s := &SqsHandler{
			logger: logging.NewLogger(),
		}
		t.Run(c.name, func(t *testing.T) {
			got := s.getResourceRegion(ctx, c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetResourceGroupName(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		input prowlerFinding
		want  string
	}{
		{
			name: "OK one group name",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{Group: prowlerGroup{Name: "group1"}},
				},
			},
			want: "group1",
		},
		{
			name: "OK two group names",
			input: prowlerFinding{
				Resources: []prowlerResource{
					{Group: prowlerGroup{Name: "group1"}},
					{Group: prowlerGroup{Name: "group2"}},
				},
			},
			want: "group1",
		},
		{
			name: "no group name",
			input: prowlerFinding{
				Resources: []prowlerResource{},
			},
			want: "",
		},
	}
	for _, c := range cases {
		s := &SqsHandler{
			logger: logging.NewLogger(),
		}
		t.Run(c.name, func(t *testing.T) {
			got := s.getResourceGroupName(ctx, c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
