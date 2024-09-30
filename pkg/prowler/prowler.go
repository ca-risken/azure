package prowler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/ca-risken/common/pkg/logging"
)

type prowlerServiceClient interface {
	run(ctx context.Context, subscription_id string, unixTime int64) (*[]prowlerFinding, error)
}

type ProwlerClient struct {
	ProwlerCommand string
	logger         logging.Logger
}

func NewProwlerClient(l logging.Logger, command string) prowlerServiceClient {
	return &ProwlerClient{
		ProwlerCommand: command,
		logger:         l,
	}
}

func (c *ProwlerClient) run(ctx context.Context, subscription_id string, unixNano int64) (*[]prowlerFinding, error) {
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
	if len(buf) > 0 {
		if err := json.Unmarshal(buf, &findings); err != nil {
			errRemove := c.removeTempDir(output)
			if errRemove != nil {
				c.logger.Warnf(ctx, "Failed to remove temp files. error: %w", errRemove)
			}
			return nil, fmt.Errorf("failed parse result JSON. file: %s, error: %+v", outputJson, err)
		}
	}

	// Remove temp dir
	if err = c.removeTempDir(output); err != nil {
		return nil, fmt.Errorf("failed to remove temp files. error: %w", err)
	}
	return &findings, nil
}

func (c *ProwlerClient) removeTempDir(resutlFilePath string) error {
	if err := os.RemoveAll(resutlFilePath); err != nil {
		return err
	}
	return nil
}

const (
	resultPASS = "PASS"
	resultFAIL = "FAIL"
)
