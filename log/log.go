package log

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
)

var (
	logCh      = make(chan Event, 1000)
	observable = NewObservable[Event](logCh)
	level      = INFO
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "15:04:05",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

// Subscribe 允许 GUI 和外部组件动态接收并显示日志
func Subscribe() (Subscription[Event], error) {
	return observable.Subscribe()
}

func Infoln(format string, v ...any) {
	event := newLog(INFO, format, v...)
	select {
	case logCh <- event:
	default:
	}
	print(event)
}

func Warnln(format string, v ...any) {
	event := newLog(WARNING, format, v...)
	select {
	case logCh <- event:
	default:
	}
	print(event)
}

func Errorln(format string, v ...any) {
	event := newLog(ERROR, format, v...)
	select {
	case logCh <- event:
	default:
	}
	print(event)
}

func Debugln(format string, v ...any) {
	event := newLog(DEBUG, format, v...)
	select {
	case logCh <- event:
	default:
	}
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
