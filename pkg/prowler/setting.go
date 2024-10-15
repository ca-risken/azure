package prowler

import (
	"embed"

	"github.com/ca-risken/common/pkg/prowler"
)

//go:generate cp ../../prowler.yaml ./yaml/

//go:embed yaml/prowler.yaml
var embeddedYaml embed.FS

const (
	PROWLER_FILE = "yaml/prowler.yaml"
)

func loadProwlerSetting(path string) (*prowler.ProwlerSetting, error) {
	if path != "" {
		return prowler.LoadProwlerSetting(path)
	}
	// default setting
	yamlFile, err := embeddedYaml.ReadFile(PROWLER_FILE)
	if err != nil {
		return nil, err
	}
	return prowler.ParseProwlerSettingYaml(yamlFile)
}
