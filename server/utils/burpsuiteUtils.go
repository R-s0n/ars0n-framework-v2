package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

func PopulateBurpsuite(urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided")
	}

	proxyIP, proxyPort := GetBurpSuiteProxySettings()
	
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

	log.Printf("[INFO] Starting Burpsuite population for %d URLs through proxy %s:%d", len(urls), proxyIP, proxyPort)

	successCount := 0
	errorCount := 0

	for i, urlStr := range urls {
		if urlStr == "" {
			continue
		}

		log.Printf("[DEBUG] Requesting URL %d/%d: %s", i+1, len(urls), urlStr)

		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			log.Printf("[ERROR] Failed to create request for URL %s: %v", urlStr, err)
			errorCount++
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed to make request to URL %s through proxy: %v", urlStr, err)
			errorCount++
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("[WARN] Failed to read response body from URL %s: %v", urlStr, err)
		} else {
			log.Printf("[DEBUG] Successfully requested URL %s - Status: %d, Body length: %d", urlStr, resp.StatusCode, len(body))
			successCount++
		}
	}

	log.Printf("[INFO] Burpsuite population completed: %d successful, %d errors", successCount, errorCount)

	return nil
}

