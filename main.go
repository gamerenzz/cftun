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
		go s.Run(server.GetBuildInfo(BuildType, CloudflaredVersion), quickData)
	}
}

func printVersion() {
	bInfo := server.GetBuildInfo(BuildType, CloudflaredVersion)
	fmt.Printf("GoOS: %s\nGoArch: %s\nGoVersion: %s\nBuildType: %s\nCftunVersion: %s\nBuildDate: %s\n",
		bInfo.GoOS, bInfo.GoArch, bInfo.GoVersion, bInfo.BuildType, Version, BuildDate)
}

func main() {
	if showVersion {
		printVersion()
		return
	}

	// 核心安全升级：在 Windows 环境下强制拦截防双开/多开冲突
	if runtime.GOOS == "windows" {
		if client.CheckSingleInstance() {
			syscall.ExitProcess(0)
		}
	}

	// 判断 Windows 环境下是否直接双击启动 (没有任何命令行参数)
	if runtime.GOOS == "windows" && configFile == "" && token == "" && !isQuick {
		log.Infoln("[System] Double-click detected. Launching Windows Panel...")
		client.StartWindowsGUI(runCoreEngine)
		return
	}

	// 命令行带参数启动逻辑
	if token != "" || isQuick {
		var warp *server.Warp
		if proxy4 || proxy6 {
			warp = &server.Warp{
				Auto:   true,
				Port:   uint16(port),
				Proxy4: proxy4,
				Proxy6: proxy6,
			}
		}
		if isQuick {
			token = "quick"
		} else if token == "quick" {
			isQuick = true
		}
		srv := &server.Config{
			Token:  token,
			HaConn: 4,
			Warp:   warp,
		}
		go srv.Run(server.GetBuildInfo(BuildType, CloudflaredVersion), quickData)
	} else {
		runCoreEngine()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	if tunName != "" {
		client.DeleteTunDevice(tunName)
	}
}
