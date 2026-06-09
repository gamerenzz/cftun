package log

import (
	"fmt"
	"sync"

	mainLog "github.com/fmnx/cftun/log" // 引入主日志系统
	"go.uber.org/zap"
)

var (
	_globalMu sync.RWMutex
	_globalL  *Logger
	_globalS  *SugaredLogger
)

func init() {
	SetLogger(zap.Must(zap.NewProduction()))
}

func NewLeveled(l Level, options ...Option) (*Logger, error) {
	switch l {
	case SilentLevel:
		return zap.NewNop(), nil
	case DebugLevel:
		return zap.NewDevelopment(options...)
	case InfoLevel, WarnLevel, ErrorLevel, DPanicLevel, PanicLevel, FatalLevel:
		cfg := zap.NewProductionConfig()
		cfg.Level.SetLevel(l)
		return cfg.Build(options...)
	default:
		return nil, fmt.Errorf("invalid level: %s", l)
	}
}

func SetLogger(logger *Logger) {
	_globalMu.Lock()
	defer _globalMu.Unlock()
	_globalL = logger.WithOptions(pkgCallerSkip)
	_globalS = _globalL.Sugar()
	_globalE.setLogger(_globalS)
}

func logf(lvl Level, template string, args ...any) {
	_globalMu.RLock()
	s := _globalS
	_globalMu.RUnlock()
	s.Logf(lvl, template, args...)

	// 核心修复：同步将底层的虚拟网卡、gVisor协议栈、TCP/UDP隧道中继日志路由到主日志包，使其流入 GUI 框中呈现
	msg := fmt.Sprintf(template, args...)
	switch lvl {
	case DebugLevel:
		mainLog.Debugln(msg)
	case InfoLevel:
		mainLog.Infoln(msg)
	case WarnLevel:
		mainLog.Warnln(msg)
	case ErrorLevel:
		mainLog.Errorln(msg)
	case FatalLevel:
		mainLog.Fatalln(msg)
	}
}

func Debugf(template string, args ...any) {
	logf(DebugLevel, template, args...)
}

func Infof(template string, args ...any) {
	logf(InfoLevel, template, args...)
}

func simplf(lvl Level, template string, args ...any) {
	logf(lvl, template, args...)
}

func Warnf(template string, args ...any) {
	logf(WarnLevel, template, args...)
}

func Errorf(template string, args ...any) {
	logf(ErrorLevel, template, args...)
}

func Fatalf(template string, args ...any) {
	logf(FatalLevel, template, args...)
}
