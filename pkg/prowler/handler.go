package prowler

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/azure/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/azure"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type SqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	azureClient   azure.AzureServiceClient
	prowler       prowlerServiceClient
	logger        logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	azc azure.AzureServiceClient,
	prowler prowlerServiceClient,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient: fc,
		alertClient:   ac,
		azureClient:   azc,
		prowler:       prowler,
		logger:        l,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageAzure(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start Prowler scan, RequestID=%s", requestID)
	s.logger.Infof(ctx, "start getRelAzureDataSource, RequestID=%s", requestID)
	relAzureDataSource, err := s.getRelAzureDataSource(ctx, msg.ProjectID, msg.AzureID, msg.AzureDataSourceID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get relAzureDataSource: project_id=%d, azure_id=%d, azure_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.AzureID, msg.AzureDataSourceID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end getRelAzureDataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(relAzureDataSource)

	// Get Prowler
	s.logger.Infof(ctx, "start Run prowler, RequestID=%s", requestID)
	tspan, tctx := tracer.StartSpanFromContext(ctx, "runProwler")
	result, err := s.prowler.run(tctx, relAzureDataSource.SubscriptionId)
	tspan.Finish(tracer.WithError(err))
	s.logger.Infof(ctx, "end Run prowler, RequestID=%s", requestID)
	if err != nil {
		err = fmt.Errorf("failed to run Prowler scan: project_id=%d, azure_id=%d, azure_data_source_id=%d, err=%w",
			msg.ProjectID, msg.AzureID, msg.AzureDataSourceID, err)
		s.logger.Error(ctx, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "start put finding, RequestID=%s", requestID)

	err = s.makeFindingBatchForUpsert(ctx, msg.ProjectID, relAzureDataSource.SubscriptionId, result)
	if err != nil {
		err = fmt.Errorf("failed to make finding batch: project_id=%d, azure_id=%d, azure_data_source_id=%d, err=%w",
			msg.ProjectID, msg.AzureID, msg.AzureDataSourceID, err)
		s.logger.Error(ctx, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "end put finding, RequestID=%s", requestID)

	// Clear score for inactive findings
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.AzureProwlerDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{relAzureDataSource.SubscriptionId},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. SubscriptionID: %v, error: %v", relAzureDataSource.SubscriptionId, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end update scan status, RequestID=%s", requestID)
	s.logger.Infof(ctx, "end Prowler scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *SqsHandler) updateStatusToError(ctx context.Context, scanStatus *azure.AttachRelAzureDataSourceRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
}

func (s *SqsHandler) getRelAzureDataSource(ctx context.Context, projectID, azureID, azureDataSourceID uint32) (*azure.RelAzureDataSource, error) {
	data, err := s.azureClient.GetRelAzureDataSource(ctx, &azure.GetRelAzureDataSourceRequest{
		ProjectId:         projectID,
		AzureId:           azureID,
		AzureDataSourceId: azureDataSourceID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.RelAzureDataSource == nil {
		return nil, fmt.Errorf("no rel_azure_data_source data, project_id=%d, azure_id=%d, azure_data_source_Id=%d", projectID, azureID, azureDataSourceID)
	}
	return data.RelAzureDataSource, nil
}

func (s *SqsHandler) updateScanStatusError(ctx context.Context, putData *azure.AttachRelAzureDataSourceRequest, statusDetail string) error {
	putData.RelAzureDataSource.Status = azure.Status_ERROR
	putData.RelAzureDataSource.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatusSuccess(ctx context.Context, putData *azure.AttachRelAzureDataSourceRequest) error {
	putData.RelAzureDataSource.Status = azure.Status_OK
	return s.updateScanStatus(ctx, putData)
}

func (s *SqsHandler) updateScanStatus(ctx context.Context, putData *azure.AttachRelAzureDataSourceRequest) error {
	resp, err := s.azureClient.AttachRelAzureDataSource(ctx, putData)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update RelAzureDataSource status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}
