package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/fmnx/cftun/client"
	"github.com/fmnx/cftun/log"
	"github.com/fmnx/cftun/server"
	"github.com/spf13/pflag"
)

type RawConfig struct {
	Server *server.Config `yaml:"server" json:"server"`
	Client *client.Config `yaml:"client" json:"client"`
}

func parseConfig(configFile string) (*RawConfig, error) {
	if configFile == "" {
		currentDir, _ := os.Getwd()
		configFile = filepath.Join(currentDir, "config.json")
	}
	buf, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", configFile)
	}
	rawCfg := &RawConfig{}
	if err := json.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}
	return rawCfg, nil
}

var (
	configFile         string
	token              string
	isQuick            bool
	proxy4             bool
	proxy6             bool
	port               int
	Version            = "2.3.0"
	BuildDate          = "unknown"
	BuildType          = "RELEASE"
	CloudflaredVersion = "2025.4.1"
	showVersion        bool
	quickData          = &server.QuickData{}
	tunName            string
)

func init() {
	pflag.StringVarP(&configFile, "config", "c", "", "")
	pflag.StringVarP(&token, "token", "t", "", "")
	pflag.BoolVarP(&isQuick, "quick", "q", false, "")
	pflag.BoolVarP(&proxy4, "proxy4", "4", false, "")
	pflag.BoolVarP(&proxy6, "proxy6", "6", false, "")
	pflag.IntVarP(&port, "port", "p", 51280, "")
	pflag.BoolVarP(&showVersion, "version", "v", false, "")

	pflag.Usage = func() {
		fmt.Println("Usage:")
		fmt.Printf("  -c,--config\tSpecify the path to the config file.\n")
		fmt.Printf("  -t,--token\tRun in server mode only using the provided token.\n")
		fmt.Printf("  -v,--version\tDisplay the version.\n")
	}
	pflag.Parse()
}

func runCoreEngine() {
	bInfo := server.GetBuildInfo(BuildType, CloudflaredVersion)
	rawConfig, err := parseConfig(configFile)
	if err != nil {
		log.Errorln("Failed to parse config file: %s", err.Error())
		return
	}

	c := rawConfig.Client
	if c != nil {
		if c.Tun != nil && c.Tun.Enable {
			tunName = c.Tun.Name
			if tunName == "" {
				tunName = "cftun0"
				c.Tun.Name = tunName
			}
		}
		c.Run()
	}

	time.Sleep(100 * time.Millisecond)

	s := rawConfig.Server
	if s != nil {
		if s.Token == "quick" {
			isQuick = true
		}
		go s.Run(bInfo, quickData)
	}
}

func main() {
	// Windows 平台，如果没有传入 CLI 命令，则自动切换至 Native 专属图形界面
	if runtime.GOOS == "windows" && configFile == "" && token == "" && !isQuick {
		log.Infoln("[System] Double-click detected. Redirecting to Graphical Panel...")
		client.StartWindowsGUI(runCoreEngine)
		return
	}

	if showVersion {
		bInfo := server.GetBuildInfo(BuildType, CloudflaredVersion)
		fmt.Printf("CFTunVersion: %s\nBuildDate: %s\n", Version, BuildDate)
		return
	}

	runCoreEngine()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	if tunName != "" {
		client.DeleteTunDevice(tunName)
	}
}

