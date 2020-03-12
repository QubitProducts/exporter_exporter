package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/common/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	winSvcCmd     = flag.String("winsvc", "", "install, uninstall, start, stop a Windows service")
	winSvcRunning = false
)

func manageService() {
	const winSvcName = "exporter_exporter"

	var err error

	switch *winSvcCmd {
	case "start":
		err = startService(winSvcName)
	case "install":
		err = installService(winSvcName, "Reverse proxy for Prometheus exporters")
	case "uninstall":
		err = uninstallService(winSvcName)
	case "stop":
		err = controlService(winSvcName, svc.Stop, svc.Stopped)
	case "":
		isIntSess, err := svc.IsAnInteractiveSession()
		if err != nil {
			log.Fatalf("Failed to determine if we are running in an interactive session: %v", err)
		}
		if !isIntSess {
			go runService(winSvcName)
			for {
				time.Sleep(time.Millisecond * 200)
				if winSvcRunning {
					break
				}
			}
		}
		return
	default:
		log.Fatalf("Unknown command '%v' for -winsvc", *winSvcCmd)
	}
	if err != nil {
		log.Fatalf("Failed to %s %s: %v", *winSvcCmd, winSvcName, err)
	}
	os.Exit(0)
}

func exePath() (string, error) {
	prog := os.Args[0]
	p, err := filepath.Abs(prog)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(p)
	if err == nil {
		if !fi.Mode().IsDir() {
			return p, nil
		}
		err = fmt.Errorf("%s is directory", p)
	}
	if filepath.Ext(p) == "" {
		p += ".exe"
		fi, err := os.Stat(p)
		if err == nil {
			if !fi.Mode().IsDir() {
				return p, nil
			}
			err = fmt.Errorf("%s is directory", p)
		}
	}
	return "", err
}

func installService(name, desc string) error {
	exepath, err := exePath()
	if err != nil {
		return fmt.Errorf("Unable to determine path of exe: %v", err)
	}
	var serviceArgs []string
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "winsvc" {
			serviceArgs = append(serviceArgs, fmt.Sprintf("-%s", f.Name))
			if f.Value.String() != "true" {
				serviceArgs = append(serviceArgs, f.Value.String())
			}
		}
	})
	if len(serviceArgs) <= 0 {
		serviceArgs = append(serviceArgs, "-config.file", fmt.Sprintf("%s\\expexp.yaml", filepath.Dir(exepath)))
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Failed while connecting to service control manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("Service with the name '%s' already exists", name)
	}
	s, err = m.CreateService(name, exepath, mgr.Config{DisplayName: name,
		StartType:   mgr.StartAutomatic,
		Description: desc}, serviceArgs...,
	)
	if err != nil {
		return fmt.Errorf("Failed while creating a new service: %v", err)
	}
	defer s.Close()
	err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("Failed while creating eventlog source: %v", err)
	}
	log.Infof("Installed service %s with args: %v", name, serviceArgs)
	return nil
}

func uninstallService(name string) error {
	controlService(name, svc.Stop, svc.Stopped)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("Failed while retrieving access to the service: %v", err)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(name)
	if err != nil {
		return fmt.Errorf("Failed while removing eventlog source: %v", err)
	}
	return nil
}

func startService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("Failed while retrieving access to the service: %v", err)
	}
	defer s.Close()
	err = s.Start()
	if err != nil {
		return fmt.Errorf("Failed while trying to start the service: %v", err)
	}
	return nil
}

func controlService(name string, c svc.Cmd, to svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("Failed while retrieving access to the service: %v", err)
	}
	defer s.Close()
	status, err := s.Control(c)
	if err != nil {
		return fmt.Errorf("Failed while sending control %d: %v", c, err)
	}
	timeout := time.Now().Add(35 * time.Second)
	for status.State != to {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("Failed while waiting for the service to change state to %d", to)
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("Failed while attempting to retrieve service status: %v", err)
		}
	}
	return nil
}

type exporterExporterService struct {
}

func (s *exporterExporterService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	winSvcRunning = true

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		default:
			log.Errorf("Unexpected control request #%d", c)
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runService(name string) {
	log.Infof("Starting service %s %s", name, Version)
	err := svc.Run(name, &exporterExporterService{})
	if err != nil {
		log.Errorf("%s service failed: %v", name, err)
		return
	}
	log.Infof("%s service stopped", name)
	os.Exit(0)
}
