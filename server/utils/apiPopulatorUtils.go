package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func ProcessApiRequest(
	method string,
	path string,
	baseURL string,
	body interface{},
	apiKey string,
	proxyIP string,
	proxyPort int,
	parameters []interface{},
	manualInputValues map[string]interface{},
) error {
	if proxyIP == "127.0.0.1" || proxyIP == "localhost" || proxyIP == "::1" {
		proxyIP = "host.docker.internal"
		log.Printf("[INFO] Detected localhost proxy IP, using host.docker.internal to access host machine")
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", proxyIP, proxyPort))
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
	}

	fullPath := path
	if len(parameters) > 0 {
		fullPath = buildPathWithParameters(path, parameters, manualInputValues)
	}

	fullURL := baseURL + fullPath
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = "https://" + fullURL
	}

	log.Printf("[DEBUG] Processing API endpoint: %s %s", strings.ToUpper(method), fullURL)

	var bodyReader io.Reader
	if body != nil {
		if manualInputValues != nil && len(manualInputValues) > 0 {
			body = mergeManualInputs(body, manualInputValues)
		}

		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
		log.Printf("[DEBUG] Request body: %s", string(bodyBytes))
	}

	req, err := http.NewRequest(strings.ToUpper(method), fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request through proxy: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read response body: %v", err)
	} else {
		log.Printf("[DEBUG] Response status: %d, Body length: %d", resp.StatusCode, len(respBody))
	}

	return nil
}

func buildPathWithParameters(path string, parameters []interface{}, manualInputValues map[string]interface{}) string {
	queryParams := url.Values{}
	pathParams := make(map[string]string)

	for _, param := range parameters {
		paramMap, ok := param.(map[string]interface{})
		if !ok {
			continue
		}

		name, nameOk := paramMap["name"].(string)
		in, inOk := paramMap["in"].(string)

		if !nameOk || !inOk {
			continue
		}

		var value string
		if manualValue, exists := manualInputValues[name]; exists {
			value = fmt.Sprintf("%v", manualValue)
		} else if example, exists := paramMap["example"]; exists {
			value = fmt.Sprintf("%v", example)
		} else if defaultVal, exists := paramMap["default"]; exists {
			value = fmt.Sprintf("%v", defaultVal)
		} else if schema, exists := paramMap["schema"].(map[string]interface{}); exists {
			if schemaExample, exists := schema["example"]; exists {
				value = fmt.Sprintf("%v", schemaExample)
			} else if schemaDefault, exists := schema["default"]; exists {
				value = fmt.Sprintf("%v", schemaDefault)
			} else {
				value = fmt.Sprintf("example_%s", name)
			}
		} else {
			value = fmt.Sprintf("example_%s", name)
		}

		switch in {
		case "query":
			queryParams.Add(name, value)
		case "path":
			pathParams[name] = value
		case "header":
		}
	}

	for key, value := range pathParams {
		path = strings.ReplaceAll(path, "{"+key+"}", value)
	}

	if len(queryParams) > 0 {
		path = path + "?" + queryParams.Encode()
	}

	return path
}

func mergeManualInputs(body interface{}, manualInputValues map[string]interface{}) interface{} {
	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		return body
	}

	for key, value := range manualInputValues {
		bodyMap[key] = value
	}

	return bodyMap
}

