// Copyright 2016 Qubit Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func watch(cfg *moduleConfig) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			log.Debug("watcher loop")
			select {
			case event := <-watcher.Events:
				log.Debug(fmt.Sprintf("Event: %v", event.Name))
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Info(fmt.Sprintf("Modified file: %v", event.Name))
					labelConfig, err := cfg.HTTP.getExtendedLabelConfig()
					if err != nil {
						log.Error("Error watcher: ", err)
					}
					cfg.HTTP.LabelExtendConfig = labelConfig
				}
			case err := <-watcher.Errors:
				log.Error("Error watcher:", err)
			}
		}
	}()

	err = watcher.Add(*cfg.HTTP.ExtendLabelsPath)
	if err != nil {
		log.Fatal(err)
	}
}
