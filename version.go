package main

import (
	"fmt"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	Version   = "unset" // Version is set at build time
	Revision  = "unset" // Revision is set at build time
	Branch    = "unset" // Branch is set at build time
	BuildUser = "unset" // BuildUser is set at build time
	BuildDate = "unset" // BuildDate is set at build time

	goVersion = runtime.Version()
)

var (
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "A metric with a constant '1' value labeled by version, revision, branch and goversion from which exporter_exporter was built.",
		},
		[]string{"version", "revision", "branch", "goversion"},
	)
)

func init() {
	prometheus.MustRegister(buildInfo)
	buildInfo.WithLabelValues(Version, Revision, Branch, goVersion).Set(1)
}

func versionStr() string {
	return fmt.Sprintf("%s-%s (from %s, built by %s on %s)", Version, Revision, Branch, BuildUser, BuildDate)
}
