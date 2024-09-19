package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func getPluginMap() map[string]string {
	m := make(map[string]string)
	m["aks"] = "CategoryAKS"
	m["app"] = "CategoryApp"
	m["appinsights"] = "CategoryAppInsights"
	m["cosmosdb"] = "CategoryCosmosDB"
	m["defender"] = "CategoryDefender"
	m["entra"] = "CategoryEntra"
	m["iam"] = "CategoryIAM"
	m["keyvault"] = "CategoryKeyVault"
	m["monitor"] = "CategoryMonitor"
	m["mysql"] = "CategoryMySQL"
	m["network"] = "CategoryNetwork"
	m["policy"] = "CategoryPolicy"
	m["postgresql"] = "CategoryPostgreSQL"
	m["sqlserver"] = "CategorySQLServer"
	m["storage"] = "CategoryStorage"
	m["vm"] = "CategoryVM"
	return m
}

func getScoreMap() map[string]string {
	m := make(map[string]string)
	m["critical"] = "scoreCritical"
	m["high"] = "scoreHigh"
	m["medium"] = "scoreMedium"
	m["low"] = "scoreLow"
	return m
}

var pluginMap = getPluginMap()
var scoreMap = getScoreMap()

type Plugin struct {
	CheckID        string            `json:"CheckID"`
	ServiceName    string            `json:"ServiceName"`
	SubServiceName string            `json:"SubServiceName"`
	ResourceType   string            `json:"ResourceType"`
	Severity       string            `json:"Severity"`
	Risk           string            `json:"Risk"`
	Remediation    pluginRemediation `json:"Remediation"`
}

type pluginRemediation struct {
	PluginRecommendation pluginRecommendation `json:"Recommendation"`
}

type pluginRecommendation struct {
	Text string `json:"Text"`
	URL  string `json:"Url"`
}

func main() {
	// argからProwlerのディレクトリを取得
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <prowler directory>", os.Args[0])
	}
	rootDir := os.Args[1]

	// jsonファイルのパスを格納するスライス
	var jsonFiles []string

	// JSONファイルを再帰的に検索
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".json" {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	var plugins []Plugin
	// 検索した全てのJSONファイルを処理
	for _, file := range jsonFiles {
		fmt.Printf("Processing file: %s\n", file)

		// JSONファイルの内容を読み込み
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Failed to read file: %s, error: %v", file, err)
			continue
		}

		// Plugin構造体に変換
		var plugin Plugin
		err = json.Unmarshal(data, &plugin)
		if err != nil {
			log.Printf("Failed to unmarshal JSON: %s, error: %v", file, err)
			continue
		}

		plugins = append(plugins, plugin)
	}
	for _, p := range plugins {
		category := getPluginCategory(p.ServiceName)
		if category == "" {
			log.Fatalf("Category not found for service: %s", p.ServiceName)
		}
		tags := getTags(p.SubServiceName, p.ResourceType)
		score := getScore(p.Severity)
		fmt.Printf(template, category, p.CheckID, score, tags, p.Risk, p.Remediation.PluginRecommendation.Text, p.Remediation.PluginRecommendation.URL)
	}
}

func getPluginCategory(serviceName string) string {
	if serviceName == "" {
		return ""
	}
	return pluginMap[serviceName]
}

func getTags(subServiceName, resourceType string) string {
	if subServiceName != "" && resourceType != "" {
		return fmt.Sprintf(`"%s", "%s"`, subServiceName, resourceType) // 両方あり
	} else if resourceType != "" {
		return fmt.Sprintf(`"%s"`, resourceType) // 片方あり①
	} else if subServiceName != "" {
		return fmt.Sprintf(`"%s"`, subServiceName) // 片方あり②
	}
	return "" // 両方なし
}

func getScore(severity string) string {
	if severity == "" {
		return ""
	}
	return scoreMap[severity]
}

var template = `	%s + "/%s": {
		Score: %s,
		Tag:   []string{%s},
		Recommend: recommend{
			Risk: "%s",
			Recommendation: "%s\n- %s",
		},
	},
`
