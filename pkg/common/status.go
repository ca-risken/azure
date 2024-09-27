package common

import (
	"time"

	"github.com/ca-risken/datasource-api/proto/azure"
)

// InitScanStatus return init AttachRelAzureDataSourceRequest data
func InitScanStatus(g *azure.RelAzureDataSource) *azure.AttachRelAzureDataSourceRequest {
	return &azure.AttachRelAzureDataSourceRequest{
		ProjectId: g.ProjectId,
		RelAzureDataSource: &azure.RelAzureDataSourceForUpsert{
			AzureId:           g.AzureId,
			AzureDataSourceId: g.AzureDataSourceId,
			ProjectId:         g.ProjectId,
			ScanAt:            time.Now().Unix(),
			Status:            azure.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:      "",
		},
	}
}
