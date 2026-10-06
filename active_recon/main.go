package active_recon

import (
	"bufio"
	"fmt"
	"net"
	"math/rand"
	"os"
	"sync"
	"time"
)

type Result struct {
	Subdomain string
	IPs       []string
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func checkWildcard(domain string) []string {
	testSub := fmt.Sprintf("%s-test.%s", randomString(12),domain)
	ips, err := net.LookupHost(testSub)
	if err == nil && len(ips) > 0 {
		return ips
	}
	return nil
}

// Parametrelere outFile *os.File eklendi
func RunBruteForce(domain, wordlistPath string, numWorkers int, outFile *os.File) {
	
	wildcardIPs := checkWildcard(domain)
	if len(wildcardIPs) > 0 {
		fmt.Printf("Wildcard DNS tespit edildi. Sahte sonuçlar filtrelenecek. (Catch-all IPs: %v)\n",wildcardIPs)
	}

	jobs := make(chan string, numWorkers)
	results := make(chan Result)

	var wg sync.WaitGroup

	var printerWg sync.WaitGroup
	printerWg.Add(1)
	go func() {
		defer printerWg.Done()
		for res := range results {
			// Terminale basılacak çıktı
			terminalOut := fmt.Sprintf("[+] Found: %s -> %v", res.Subdomain, res.IPs)
			fmt.Println(terminalOut)
			
			// Eğer kullanıcı -o ile dosya belirttiyse, dosyaya kaydet
			if outFile != nil {
				fileOut := fmt.Sprintf("%s,%v\n", res.Subdomain, res.IPs)
				outFile.WriteString(fileOut)
			}
		}
	}()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(domain, jobs, results, &wg)
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("Wordlist açılamadı: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" {
			jobs <- word
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	printerWg.Wait()
}

func worker(domain string, jobs <-chan string, results chan<- Result, wg *sync.WaitGroup, wildcardIPs []string) {
	defer wg.Done()
	
	for word := range jobs {
		subdomain := fmt.Sprintf("%s.%s", word, domain)
		ips, err := net.LookupHost(subdomain)
		
		if err == nil && len(ips) > 0 {
			// Wildcard IP filtreleme mantığı
			isWildcard := false
			if len(wildcardIPs) > 0 {
				for _, ip := range ips {
					for _, wIP := range wildcardIPs {
						if ip == wIP {
							isWildcard = true
							break
						}
					}
					if isWildcard {
						break
					}
				}
			}

			// Eğer dönen IP'ler Wildcard IP'leri ile eşleşmiyorsa, geçerli bir sonuçtur
			if !isWildcard {
				results <- Result{
					Subdomain: subdomain,
					IPs:       ips,
				}
			}
		}
	}
}