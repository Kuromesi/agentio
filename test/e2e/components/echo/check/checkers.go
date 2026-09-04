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

package check

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openkruise/agentio/test/e2e/components/echo"
)

// Visitor evaluates one parsed echo response.
type Visitor func(echo.Response) error

// Each applies a visitor to every response and includes the failed response index.
func Each(visitor Visitor) echo.Checker {
	return func(result echo.Result, _ error) error {
		if len(result.Responses) == 0 {
			return errors.New("received no responses")
		}
		for index, response := range result.Responses {
			if err := visitor(response); err != nil {
				return fmt.Errorf("response %d: %w", index, err)
			}
		}
		return nil
	}
}

func And(checkers ...echo.Checker) echo.Checker {
	return func(result echo.Result, callErr error) error {
		for _, checker := range checkers {
			if checker == nil {
				continue
			}
			if err := checker(result, callErr); err != nil {
				return err
			}
		}
		return nil
	}
}

func NoError() echo.Checker {
	return func(_ echo.Result, callErr error) error {
		return callErr
	}
}

func Error() echo.Checker {
	return func(_ echo.Result, callErr error) error {
		if callErr == nil {
			return errors.New("expected an error, got none")
		}
		var exitErr interface {
			error
			Exited() bool
			ExitStatus() int
		}
		if !errors.As(callErr, &exitErr) || !exitErr.Exited() || exitErr.ExitStatus() == 0 {
			return fmt.Errorf("expected the request command to fail, got an infrastructure or response-processing error: %w", callErr)
		}
		return nil
	}
}

func ErrorContains(want string) echo.Checker {
	return func(_ echo.Result, callErr error) error {
		if callErr == nil {
			return fmt.Errorf("expected an error containing %q, got none", want)
		}
		if !strings.Contains(callErr.Error(), want) {
			return fmt.Errorf("call error %q does not contain %q", callErr, want)
		}
		return nil
	}
}

func Status(want int) echo.Checker {
	return func(result echo.Result, _ error) error {
		if len(result.Responses) == 0 {
			return fmt.Errorf("received no responses; want status %d", want)
		}
		for index, response := range result.Responses {
			if response.StatusCode != want {
				return fmt.Errorf("response %d status = %d, want %d", index, response.StatusCode, want)
			}
		}
		return nil
	}
}

// NotStatus rejects any response with the given status code.
func NotStatus(want int) echo.Checker {
	return Each(func(response echo.Response) error {
		if response.StatusCode == want {
			return fmt.Errorf("status = %d, want not %d", response.StatusCode, want)
		}
		return nil
	})
}

// RequestHeader requires every response to contain the request header value.
func RequestHeader(key, want string) echo.Checker {
	return Each(func(response echo.Response) error {
		return headerValue(response.RequestHeaders, "request", key, want)
	})
}

// ResponseHeader requires every response to contain the response header value.
func ResponseHeader(key, want string) echo.Checker {
	return Each(func(response echo.Response) error {
		return headerValue(response.ResponseHeaders, "response", key, want)
	})
}

func headerValue(headers http.Header, kind, key, want string) error {
	for _, value := range headers.Values(key) {
		if value == want {
			return nil
		}
	}
	return fmt.Errorf("%s header %q does not contain %q", kind, key, want)
}

// BodyContains requires every response to contain the text in raw content or a body field.
func BodyContains(want string) echo.Checker {
	return Each(func(response echo.Response) error {
		if strings.Contains(response.RawContent, want) {
			return nil
		}
		for _, value := range response.Body {
			if strings.Contains(value, want) {
				return nil
			}
		}
		return fmt.Errorf("body does not contain %q", want)
	})
}

func NoErrorAndStatus(want int) echo.Checker {
	return And(NoError(), Status(want))
}

func OK() echo.Checker {
	return NoErrorAndStatus(200)
}

func ReachedWorkloads(want int) echo.Checker {
	return func(result echo.Result, _ error) error {
		workloads := make(map[string]struct{})
		for _, response := range result.Responses {
			if response.Hostname != "" {
				workloads[response.Hostname] = struct{}{}
			}
		}
		if len(workloads) != want {
			return fmt.Errorf("reached %d workload(s), want %d", len(workloads), want)
		}
		return nil
	}
}
