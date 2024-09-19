package prowler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/ca-risken/common/pkg/logging"
)

type prowlerServiceClient interface {
	run(ctx context.Context, subscription_id string) (*[]prowlerFinding, error)
}

type ProwlerClient struct {
	ProwlerCommand    string
	logger            logging.Logger
	AzureClientID     string
	AzureTenantID     string
	AzureClientSecret string
}

func NewProwlerClient(l logging.Logger, command, azureClientID, azureTenantID, azureClientSecret string) prowlerServiceClient {
	return &ProwlerClient{
		ProwlerCommand:    command,
		logger:            l,
		AzureClientID:     azureClientID,
		AzureTenantID:     azureTenantID,
		AzureClientSecret: azureClientSecret,
	}
}

func (c *ProwlerClient) run(ctx context.Context, subscription_id string) (*[]prowlerFinding, error) {
	unixNano := time.Now().UnixNano()

	// Exec Prowler
	result, err := c.execProwler(ctx, subscription_id, unixNano)
	if err != nil {
		c.logger.Errorf(ctx, "Failed to exec azure, subscription_id=%s, err=%+v", subscription_id, err)
		return nil, err
	}

	return result, nil
}

func (c *ProwlerClient) execProwler(ctx context.Context, subscription_id string, unixNano int64) (*[]prowlerFinding, error) {
	output := fmt.Sprintf("/tmp/%s_%d_result", subscription_id, unixNano)
	fileName := fmt.Sprintf("%s.ocsf.json", subscription_id)
	outputJson := output + "/" + fileName
	cmd := exec.Command(
		c.ProwlerCommand, "azure", "--sp-env-auth", "--subscription-ids", subscription_id,
		"-M", "json-ocsf", "-F", subscription_id,
		"-o", output, "--ignore-exit-code-3",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed exec azure. error: %+v, detail: %s", err, stderr.String())
	}
	resultFile, err := os.Open(outputJson)
	if err != nil {
		return nil, fmt.Errorf("failed to open result file. file: %s, error: %+v", outputJson, err)
	}
	defer resultFile.Close()
	buf, err := io.ReadAll(resultFile)
	if err != nil {
		return nil, err
	}
	c.logger.Debugf(ctx, "Result file Length: %d", len(buf))

	var findings []prowlerFinding
	if len(buf) == 0 {
		return &findings, nil // empty
	}
	if err := json.Unmarshal(buf, &findings); err != nil {
		return nil, fmt.Errorf("failed parse result JSON. file: %s, error: %+v", outputJson, err)
	}

	// Remove temp files
	if err = c.removeTempFiles(outputJson); err != nil {
		return nil, fmt.Errorf("failed to remove temp files. error: %w", err)
	}
	return &findings, nil
}

func (c *ProwlerClient) removeTempFiles(resutlFilePath string) error {
	if err := os.Remove(resutlFilePath); err != nil {
		return err
	}
	return nil
}

const (
	resultPASS = "PASS"
	resultFAIL = "FAIL"
)
