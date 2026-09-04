// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package echo

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Response struct {
	ID              string
	StatusCode      int
	Hostname        string
	Host            string
	Protocol        string
	URL             string
	RawContent      string
	Body            map[string]string
	RequestHeaders  http.Header
	ResponseHeaders http.Header
}

var framePattern = regexp.MustCompile(`^\[(\d+)(?: (body|error))?\]\s?(.*)$`)

func ParseResponses(output string) ([]Response, error) {
	frames := make(map[int][]string)
	order := make([]int, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		match := framePattern.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		id, _ := strconv.Atoi(match[1])
		if _, found := frames[id]; !found {
			order = append(order, id)
		}
		line := match[3]
		if match[2] != "" {
			line = match[2] + "] " + line
		}
		frames[id] = append(frames[id], line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(order) == 0 {
		return nil, errors.New("echo output contains no request frames")
	}
	sort.Ints(order)
	responses := make([]Response, 0, len(order))
	for _, id := range order {
		response := Response{
			ID: strconv.Itoa(id), Body: make(map[string]string),
			RequestHeaders: make(http.Header), ResponseHeaders: make(http.Header),
		}
		response.RawContent = strings.Join(frames[id], "\n")
		for _, line := range frames[id] {
			body := false
			if strings.HasPrefix(line, "body] ") {
				body = true
				line = strings.TrimPrefix(line, "body] ")
			}
			key, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			if body {
				response.Body[key] = value
			}
			switch key {
			case "X-Request-Id":
				response.ID = value
			case "StatusCode":
				code, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parse request %d StatusCode %q: %w", id, value, err)
				}
				response.StatusCode = code
			case "Hostname":
				response.Hostname = value
			case "Host":
				response.Host = value
			case "Proto":
				response.Protocol = value
			case "URL":
				response.URL = value
			case "RequestHeader":
				addHeader(response.RequestHeaders, value)
			case "ResponseHeader":
				addHeader(response.ResponseHeaders, value)
			}
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func addHeader(headers http.Header, value string) {
	key, headerValue, found := strings.Cut(value, ":")
	if found {
		headers.Add(key, headerValue)
	}
}
