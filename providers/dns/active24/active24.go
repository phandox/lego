package active24

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	EnvApiKey          = "ACTIVE24_API_KEY"
	EnvApiUrl          = "ACTIVE24_API_URL"
	DefaultEndpointUrl = "https://api.active24.com/"
)

type dnsRecordTXTCreate struct {
	Name string `json:"name"` // Name of the record.
	Text string `json:"text"`
	TTL  int    `json:"ttl"` // Time to live.
}

type dnsRecordTXT struct {
	Name   string `json:"name"`
	TTL    int    `json:"ttl"`
	Text   string `json:"text"`
	HashId string `json:"hashId"`
	Type   string `json:"type"`
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	apiKey   string
	endpoint string
}

type DNSProvider struct {
	config *Config
	c      HTTPClient
}

func NewDNSProviderConfig() (*Config, error) {
	values, err := env.Get(EnvApiKey)
	if err != nil {
		return nil, err
	}
	return &Config{
		apiKey:   values[EnvApiKey],
		endpoint: env.GetOrDefaultString(EnvApiUrl, DefaultEndpointUrl),
	}, nil
}

func NewDNSProvider() (*DNSProvider, error) {
	conf, err := NewDNSProviderConfig()
	if err != nil {
		return nil, err
	}
	return &DNSProvider{conf, &http.Client{
		Timeout: 3 * time.Second,
	}}, nil
}

func (d *DNSProvider) newTXTRecord(name, text, domain string, ttl int) (*http.Request, error) {
	body, err := json.Marshal(dnsRecordTXTCreate{
		Name: name,
		Text: text,
		TTL:  ttl,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/dns/%s/txt/v1", d.config.endpoint, domain), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", d.config.apiKey))
	log.Infof("[%s]: prepared TXT DNS record call: %s with payload: %s", "active24", req.URL, req.Body)
	return req, nil
}

func extractSecondLvlDomain(domain string) (string, error) {
	tokens := strings.Split(domain, ".")
	if len(tokens) < 2 {
		return "", errors.New("can't parse second-level domain")
	}
	if tokens[len(tokens)-1] == "" || tokens[len(tokens)-2] == "" {
		return "", errors.New("can't parse second-level domain")
	}
	return strings.Join(tokens[len(tokens)-2:], "."), nil

}

func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	// TODO better error handling / reporting
	// TODO better URL parsing (rather than raw strings)
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	log.Infof("[%s] ")
	sld, err := extractSecondLvlDomain(domain)
	if err != nil {
		return err
	}
	req, err := d.newTXTRecord(dns01.UnFqdn(fqdn), value, sld, 300)
	resp, err := d.c.Do(req)
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("authentication was not successful")
	case http.StatusForbidden:
		return fmt.Errorf("not authorized")
	case http.StatusTooManyRequests:
		return errors.New("rate limited, try again later")
	case http.StatusInternalServerError:
		return errors.New("internal server error, try again later")
	case http.StatusNoContent:
		return nil
	case http.StatusBadRequest:
		return errors.New("validation error, check your payload")
	default:
		return fmt.Errorf("unhandled http status response. Status code: %v\n Response: %v\n Request: %v\n", resp.StatusCode, resp, req)
	}
}

func (d *DNSProvider) deleteTXTRecord(domain, hashId string) error {
	u, err := url.Parse(fmt.Sprintf("%s/dns/%s/%s/v1", d.config.endpoint, domain, hashId))
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", d.config.apiKey))

	resp, err := d.c.Do(req)
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusBadRequest:
		return errors.New("DNS record to delete not found")
	case http.StatusUnauthorized:
		return errors.New("invalid token")
	case http.StatusForbidden:
		return errors.New("not allowed to delete that record")
	case http.StatusTooManyRequests:
		return errors.New("rate limited, too many requests")
	case http.StatusInternalServerError:
		return errors.New("server side error")
	default:
		return errors.New("unexpected status code returned")
	}
}

func (d *DNSProvider) getDomainHashId(domain string, fqdn string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/dns/%s/records/v1", d.config.endpoint, domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", d.config.apiKey))
	resp, err := d.c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var records []map[string]interface{}
	var hashIds []string
	err = json.Unmarshal(body, &records)
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		var txtRec dnsRecordTXT
		val, ok := r["type"]
		if !ok {
			continue
		}
		if val != "TXT" {
			continue
		}
		if err := mapstructure.Decode(r, &txtRec); err != nil {
			return nil, err
		}
		if txtRec.Name != fqdn {
			continue
		}
		hashIds = append(hashIds, txtRec.HashId)
	}
	return hashIds, nil
}

func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	sld, err := extractSecondLvlDomain(domain)
	if err != nil {
		return err
	}
	ids, err := d.getDomainHashId(sld, dns01.UnFqdn(fqdn))
	for _, i := range ids {
		err = d.deleteTXTRecord(sld, i)
		if err != nil {
			return err
		}
	}
	return nil
}
