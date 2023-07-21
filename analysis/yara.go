package analysis

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Velocidex/go-yara"
	getter "github.com/hashicorp/go-getter"
)

// YaraScanner - struct that holds compiler and rules.
type YaraScanner struct {
	Compiler  *yara.Compiler
	Rules     *yara.Rules
	RulesPath string
}

func (y *YaraScanner) AddRule(rule string) bool {
	f, err := os.Open(rule)
	defer f.Close()
	if err == nil {
		// Test rule is valid by using a test compiler.
		tempCompiler, err := yara.NewCompiler()
		if err != nil {
			return false
		}
		err = tempCompiler.AddFile(f, "all")
		if err == nil {
			f2, err := os.Open(rule)
			defer f2.Close()
			err = y.Compiler.AddFile(f2, "all")
			if err == nil {
				return true
			}
		}
	}

	return false
}

// LoadRules - Loads YARA rules into compiler.
func (y *YaraScanner) LoadRules() {
	rules := []string{}

	err := filepath.Walk(y.RulesPath,
		func(path string, info os.FileInfo, err error) error {
			if strings.Contains(path, ".yar") {
				rules = append(rules, path)
			}
			return nil
		})
	if err != nil {
		fmt.Println(err)
	}

	y.Compiler, err = yara.NewCompiler()
	if err != nil {
		fmt.Printf("Failed to initialize yara compiler: %s\n", err)
		os.Exit(-1)
	}

	numIgnored := 0
	for _, rule := range rules {
		added := y.AddRule(rule)
		if added == false {
			numIgnored++
		}
	}

	if numIgnored > 0 {
		fmt.Printf("Failed to load %d yara rules.\n", numIgnored)
	}

	y.Rules, err = y.Compiler.GetRules()
	if err != nil {
		fmt.Printf("Failed to compile rules: %s", err)
		os.Exit(-1)
	}
}

// DownloadLatestRules - Downloads the latest yara rules from a url.
func (y *YaraScanner) DownloadLatestRules(url string) {
	var mode getter.ClientMode
	mode = getter.ClientModeDir

	// Get the wd
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting working directory: %s", err)
		os.Exit(-1)
	}

	yaraRulesPath := y.RulesPath

	ctx, _ := context.WithCancel(context.Background())
	opts := []getter.ClientOption{}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     url,
		Dst:     yaraRulesPath,
		Pwd:     pwd,
		Mode:    mode,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	} else {
		fmt.Printf("Updated to latest YARA ruleset from %s\n", url)
	}
}

// AnalyzeYARAFile - Gets data from file and passes to AnalyzeYARA.
func (y *YaraScanner) AnalyzeYARAFile(filepath string) []yara.MatchRule {

	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	m, _ := y.Rules.ScanMem(b, 0, 0)
	return m
}
