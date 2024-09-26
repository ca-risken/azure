package prowler

import (
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
)

const unixNano = int64(999999999)

func TestRun(t *testing.T) {
	testClient := &ProwlerClient{
		ProwlerCommand: "echo",
		logger:         logging.NewLogger(),
	}
	cases := []struct {
		name     string
		input    string
		fileDesc string
		want     *[]prowlerFinding
		wantErr  bool
	}{
		{
			name:  "OK",
			input: "test-project",
			want:  &[]prowlerFinding{},
		},
		{
			name:     "error",
			input:    "test-project",
			fileDesc: `{`,
			want:     nil,
			wantErr:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			// create test result file
			createTempFile(c.input, unixNano, c.fileDesc)
			got, err := testClient.run(ctx, c.input, unixNano)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if got == nil && c.want == nil {
				return
			}
			if got == nil || c.want == nil {
				t.Fatalf("either got or want is not nil: want=%+v, got=%+v", c.want, got)
			}
			if reflect.DeepEqual(*got, *c.want) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func createTempFile(subscriptionID string, nanoUnix int64, fileDesc string) {
	err := os.Mkdir(fmt.Sprintf("/tmp/%s_%d_result", subscriptionID, nanoUnix), 0755)
	if err != nil {
		log.Fatalf("Failed to create a temp directory: %v", err)
	}
	f, err := os.Create(fmt.Sprintf("/tmp/%s_%d_result/%s.ocsf.json", subscriptionID, nanoUnix, subscriptionID))
	if err != nil {
		log.Fatalf("Failed to create a temp file: %v", err)
	}
	defer f.Close()
	_, err = f.Write([]byte(fileDesc))
	if err != nil {
		log.Fatalf("Failed to write to a temp file: %v", err)
	}
}
