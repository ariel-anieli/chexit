package main

import "fmt"

const (
	CLOSE int = iota
	INFO
	DEBUG
	ERROR
)

type logMessage struct {
	level   int
	message string
}

type logger struct{ queue chan logMessage }

func startLogger(verbose int) *logger {
	_logger := &logger{make(chan logMessage)}
	go _logger.start(verbose)
	return _logger
}

func stopLogger(logger *logger) {
	logger.queue <- logMessage{level: CLOSE}
}

func (logger *logger) start(verbose int) {
	toStr := []string{
		INFO:  "INFO",
		DEBUG: "DEBUG",
		ERROR: "ERROR",
	}

	for log := range logger.queue {
		if log.level == CLOSE {
			close(logger.queue)
			return
		}

		if verbose > 0 {
			fmt.Printf("%s: %s\n", toStr[log.level], log.message)
		} else if log.level == INFO || log.level == ERROR {
			fmt.Printf("%s\n", log.message)
		}
	}
}

func (logger *logger) info(message string) {
	logger.queue <- logMessage{level: INFO, message: message}
}

func (logger *logger) debug(message string) {
	logger.queue <- logMessage{level: DEBUG, message: message}
}

func (logger *logger) error(message string) {
	logger.queue <- logMessage{level: ERROR, message: message}
}
