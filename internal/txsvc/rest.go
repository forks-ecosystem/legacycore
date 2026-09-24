package txsvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

var httpClient = &http.Client{Timeout: 25 * time.Second}

func getJSON(url string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "legacycore-wallet-agent/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, truncate(string(body), 240))
	}
	return json.Unmarshal(body, out)
}

func postRaw(url string, body []byte, contentType string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "legacycore-wallet-agent/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return rb, resp.StatusCode, err
	}
	return rb, resp.StatusCode, nil
}

func parseAtomic(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

func parseAtomicRaw(rm json.RawMessage) int64 {
	if len(rm) == 0 {
		return 0
	}
	if rm[0] == '"' {
		var s string
		_ = json.Unmarshal(rm, &s)
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f)
		}
		return 0
	}
	var n float64
	if json.Unmarshal(rm, &n) == nil {
		return int64(n)
	}
	return 0
}

func pow10(n int) int64 {
	p := int64(1)
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

func formatAtomicDec(n int64, dec int, sym string) string {
	neg := n < 0
	abs := n
	if neg {
		abs = -abs
	}
	unit := pow10(dec)
	whole := abs / unit
	frac := abs % unit
	s := strconv.FormatInt(whole, 10)
	if frac > 0 {
		f := strconv.FormatInt(frac, 10)
		for len(f) < dec {
			f = "0" + f
		}
		s += "." + f
	}
	if neg {
		s = "-" + s
	}
	return s + " " + sym
}

func timeFromUnix(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
