package main

import "fmt"

var (
	Version   = "unset"
	Revision  = "unset"
	Branch    = "unset"
	BuildUser = "unset"
	BuildDate = "unset"
)

func versionStr() string {
	return fmt.Sprintf("%s-%s (from %s, built by %s on %s)", Version, Revision, Branch, BuildUser, BuildDate)
}
