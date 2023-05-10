package log

import logger "github.com/sirupsen/logrus"

type Logger struct {
}

func NewLogger() *Logger {
	return &Logger{}
}

// Infof logs a message at level Info on the standard logger.
func (l *Logger) Infof(format string, args ...interface{}) {
	logger.Infof(format, args...)
}

// Debugf logs a message at level Debug on the standard logger.
func (l *Logger) Debugf(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}

// Errorf logs a message at level Error on the standard logger.
func (l *Logger) Errorf(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

// Fatalf logs a message at level Fatal on the standard logger.
func (l *Logger) Fatalf(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
}

// Panicf logs a message at level Panic on the standard logger.
func (l *Logger) Panicf(format string, args ...interface{}) {
	logger.Panicf(format, args...)
}

// Warnf logs a message at level Warn on the standard logger.
func (l *Logger) Warnf(format string, args ...interface{}) {
	logger.Warnf(format, args...)
}

// Info logs a message at level Info on the standard logger.
func (l *Logger) Info(args ...interface{}) {
	logger.Infoln(args...)
}

// Debug logs a message at level Debug on the standard logger.
func (l *Logger) Debug(args ...interface{}) {
	logger.Debugln(args...)
}

// Error logs a message at level Error on the standard logger.
func (l *Logger) Error(args ...interface{}) {
	logger.Errorln(args...)
}

// Fatal logs a message at level Fatal on the standard logger.
func (l *Logger) Fatal(args ...interface{}) {
	logger.Fatalln(args...)
}

// Panic logs a message at level Panic on the standard logger.
func (l *Logger) Panic(args ...interface{}) {
	logger.Panicln(args...)
}

// Warn logs a message at level Warn on the standard logger.
func (l *Logger) Warn(args ...interface{}) {
	logger.Warnln(args...)
}
