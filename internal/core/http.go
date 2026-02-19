package core

import (
	"bytes"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

func httpPost(url, contentType string, body []byte) (*http.Response, error) {
	return httpClient.Post(url, contentType, bytes.NewReader(body))
}
