package main

import (
	"fmt"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	Version   = "unset"
	Revision  = "unset"
	Branch    = "unset"
	BuildUser = "unset"
	BuildDate = "unset"
	GoVersion = runtime.Version()
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
	buildInfo.WithLabelValues(Version, Revision, Branch, GoVersion).Set(1)
}

func versionStr() string {
	return fmt.Sprintf("%s-%s (from %s, built by %s on %s)", Version, Revision, Branch, BuildUser, BuildDate)
}
