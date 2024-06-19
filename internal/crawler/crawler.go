package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gocolly/colly"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Crawler struct {
	Logger      *zap.Logger
	RedisClient *redis.Client
}

type Vulnerability struct {
	Name               string   `json:"name"`
	CVEID              string   `json:"CVEID"`
	PublishedDate      string   `json:"publishDate"`
	LastModified       string   `json:"lastModified"`
	Description        string   `json:"description"`
	VulnerableVersions []string `json:"vulnerableVersions"`
	NVDScore           string   `json:"NVDScore"`
	CNAScore           string   `json:"CNAScore"`
}

func (crawler *Crawler) ExtractVulnerabilitiesLinks(query string) []string {
	vulnerabilitiesLinks := []string{}
	baseLink := generateLink(query)
	counter := 0

	for {
		finalLink := fmt.Sprintf("%s&startIndex=%d", baseLink, counter)
		vuls := crawler.ExtractVulnerabilityLinksPerPage(finalLink, query)

		if len(vuls) != 0 {
			vulnerabilitiesLinks = append(vulnerabilitiesLinks, vuls...)
			counter += 20
		} else {
			break
		}
	}

	crawler.Logger.Info(fmt.Sprintf("Web Crawler has found %d vulnerabilities for %s", len(vulnerabilitiesLinks), query))
	return vulnerabilitiesLinks
}

func (crawler *Crawler) ExtractVulnerabilityLinksPerPage(link, query string) []string {
	c := colly.NewCollector()
	vulnerabiliyLinks := []string{}

	c.OnHTML("tr th strong", func(h *colly.HTMLElement) {
		vulnerability := h.ChildText("a")
		vulnerabiliyLinks = append(vulnerabiliyLinks, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%v", vulnerability))
		crawler.Logger.Info(fmt.Sprintf("New vulnerability is found for %s - %s", query, vulnerability))
	})

	c.Visit(link)

	return vulnerabiliyLinks
}

func (crawler *Crawler) ExtractVulnerabilitiesDetails(query string, vulnerabilitiesLinks []string) []Vulnerability {
	crawler.Logger.Info(fmt.Sprintf("Web Scrapper is started to extract data of %d vulnerabilities", len(vulnerabilitiesLinks)))

	// Create a channel to handle the results
	results := make(chan Vulnerability, len(vulnerabilitiesLinks))
	// Create a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup
	concurrentWorkers := 10
	sem := make(chan struct{}, concurrentWorkers)

	for _, link := range vulnerabilitiesLinks {
		wg.Add(1)
		sem <- struct{}{}

		go func(link string) {
			defer wg.Done()
			defer func() { <-sem }()
			vuln := crawler.scrapeVulnerabilityDetails(query, link)
			results <- vuln
		}(link)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulnerSlice []Vulnerability
	for vuln := range results {
		vulnerSlice = append(vulnerSlice, vuln)
	}

	return vulnerSlice
}

func (crawler *Crawler) scrapeVulnerabilityDetails(query, link string) Vulnerability {
	var vuln Vulnerability

	splitedLink := strings.Split(link, "/")
	val, err := crawler.RedisClient.Get(context.Background(), splitedLink[len(splitedLink)-1]).Result()

	if err != nil {
		crawler.Logger.Info(fmt.Sprintf("Cache miss for %s - %s", query, splitedLink[len(splitedLink)-1]))
	} else {
		json.Unmarshal([]byte(val), &vuln)
		return vuln
	}

	c := colly.NewCollector()

	// Extract the description of vulnerability
	c.OnHTML("div.col-lg-9:nth-child(1) > p:nth-child(3)", func(h *colly.HTMLElement) {
		vuln.Description = h.Text
	})
	// Extract the description of vulnerability if the first one doesn't work
	c.OnHTML("div.col-lg-9:nth-child(1) > p:nth-child(2)", func(h *colly.HTMLElement) {
		vuln.Description = h.Text
	})
	// Extract the CVE_ID of vulnerability
	c.OnHTML("div.bs-callout:nth-child(1)", func(h *colly.HTMLElement) {
		vuln.CVEID = h.ChildText("a")
	})
	// Extract the publish date of vulnerability
	c.OnHTML("div.bs-callout:nth-child(1) > span:nth-child(8)", func(h *colly.HTMLElement) {
		vuln.PublishedDate = h.Text
	})
	// Extract the last modified date of vulnerability
	c.OnHTML("div.bs-callout:nth-child(1) > span:nth-child(12)", func(h *colly.HTMLElement) {
		vuln.LastModified = h.Text
	})
	// Extract the NVD severity score of vulnerability
	c.OnHTML("#Cvss3NistCalculatorAnchor", func(h *colly.HTMLElement) {
		vuln.NVDScore = h.Text
	})
	// Extract the CNA severity score of vulnerability
	c.OnHTML("#Cvss3CnaCalculatorAnchor", func(h *colly.HTMLElement) {
		vuln.CNAScore = h.Text
	})
	// Extract vulnerable versions
	c.OnScraped(func(r *colly.Response) {
		res, err := http.Get(link)
		if err != nil {
			log.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
		}

		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			fmt.Println("Error creating GoQuery document:", err)
			return
		}

		var result []string
		doc.Find("td[data-testid*='vuln-change-history']").Each(func(i int, e *goquery.Selection) {
			// if it's a td tag that includes a portion of the vulnerable versions
			if strings.Contains(e.Text(), "*cpe") {
				extractVulnerableVersions(e.Text(), &result)
			}
		})
		vuln.Name = query
		vuln.VulnerableVersions = result
	})

	c.Visit(link)

	jsonVulnerability, marshalErr := json.Marshal(vuln)
	if marshalErr == nil {
		crawler.RedisClient.Set(context.Background(), splitedLink[len(splitedLink)-1], jsonVulnerability, 72*time.Hour)
		// crawler.Logger.Info(fmt.Sprintf("Cache set for %s - %s", query, splitedLink[len(splitedLink)-1]))
	}

	return vuln
}

func generateLink(query string) string {
	baseUrl := "https://nvd.nist.gov/vuln/search/results"
	formType := "Basic"
	resultsType := "overview"
	queryType := "phrase"
	searchType := "all" // it could be "all" or "last3month"
	// isCpeNameSearch := false
	return fmt.Sprintf("%s?form_type=%v&results_type=%v&query=%v&queryType=%v&search_type=%v",
		baseUrl,
		formType,
		resultsType,
		query,
		queryType,
		searchType)
}

func splitBeforeSeparator(input, separator string) []string {
	var result []string
	parts := strings.Split(input, separator)

	for i, part := range parts {
		if i > 0 {
			part = separator + part
		}
		result = append(result, part)
	}

	return result
}

func extractVulnerableVersions(elementText string, result *[]string) {
	strSlice := splitBeforeSeparator(elementText, "*cpe")
	for index, str := range strSlice {
		if strings.HasPrefix(str, "*cpe") {
			if strings.Contains(str, "versions") {
				arr := splitBeforeSeparator(str, "versions")
				str = strings.TrimSpace(arr[1])
				if index != len(strSlice)-1 {
					*result = append(*result, str)
				} else {
					s := strings.Split(str, "\n")
					*result = append(*result, string(s[0]))
				}
			}
		}
	}
}
