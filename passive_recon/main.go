//Crtsh certificate Search
package passive_recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type CrtshResponse struct {
	NameValue string `json:"name_value"`
}	

func GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh isteği başarısız: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh beklenmeyen bir durum kodu döndürdü: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("yanıt okunamadı: %v", err)
	}

	var results []CrtshResponse
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("JSON ayrıştırılamadı: %v", err)
	}

	uniqueSubdomains := make(map[string]struct{})
	for _, entry := range results {
		cleanName := strings.ToLower(entry.NameValue)
		cleanName = strings.ReplaceAll(cleanName, "*","")
		lines := strings.Split(cleanName, "\n")

		for _, line := range lines {
			line = strings.ToLower(entry.NameValue)
			if strings.HasSuffix(line,domain) {
				uniqueSubdomains[line] = struct{}{}
			}
		}
	}

	var subdomains []string
	for sub := range uniqueSubdomains {
		subdomains = append(subdomains, sub)
	}

	return subdomains, nil
}