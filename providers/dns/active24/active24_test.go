package active24

import (
	"bytes"
	"errors"
	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"testing"
)

var envVals = tester.NewEnvTest(EnvApiKey, EnvApiUrl)

type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func validateHeaders(req *http.Request) error {
	expectedHeaders := []string{"Content-Type", "Authorization"}
	for _, h := range expectedHeaders {
		switch h {
		case "Content-Type":
			if v := req.Header.Get(h); v != "application/json" {
				return errors.New("content type in header not set to application/json")
			}
		case "Authorization":
			if v := req.Header.Get(h); len(v) == 0 {
				return errors.New("authorization header contains no data")
			}
		}
	}
	return nil
}
func setupFakeDNSProvider(t *testing.T, statusCode int, body []byte) *DNSProvider {
	t.Helper()
	conf, err := NewDNSProviderConfig()
	require.NoError(t, err)
	return &DNSProvider{
		config: conf,
		c: &MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
			if err := validateHeaders(req); err != nil {
				return nil, err
			}
			if body != nil {
				return &http.Response{
					StatusCode: statusCode,
					Body:       ioutil.NopCloser(bytes.NewBuffer(body)),
				}, nil

			}
			return &http.Response{StatusCode: statusCode}, nil
		},
		},
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	tt := []struct {
		desc    string
		envVars map[string]string
		want    *Config
	}{
		{
			desc: "default config",
			envVars: map[string]string{
				EnvApiKey: "qwerty123456-ok",
			},
			want: &Config{
				apiKey:   "qwerty123456-ok",
				endpoint: DefaultEndpointUrl,
			},
		},
		{
			desc: "endpoint override",
			envVars: map[string]string{
				EnvApiKey: "api-key",
				EnvApiUrl: "https://custom.api.com",
			},
			want: &Config{
				apiKey:   "api-key",
				endpoint: "https://custom.api.com",
			},
		},
	}
	for _, test := range tt {
		t.Run(test.desc, func(t *testing.T) {
			defer envVals.RestoreEnv()
			envVals.ClearEnv()
			envVals.Apply(test.envVars)

			c, err := NewDNSProviderConfig()
			if test.want != nil {
				require.Equal(t, c, test.want)
				require.NoError(t, err)
			}
		})
	}
}

func TestNewDNSProvider(t *testing.T) {
	tt := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success API key",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected: "",
		},
		{
			desc: "empty API key",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "",
			},
			expected: "some credentials information are missing: ACTIVE24_API_KEY",
		},
	}
	for _, test := range tt {
		t.Run(test.desc, func(t *testing.T) {
			defer envVals.RestoreEnv()
			envVals.ClearEnv()
			envVals.Apply(test.envVars)

			p, err := NewDNSProvider()
			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestDNSProviderPresent(t *testing.T) {
	tt := []struct {
		desc         string
		envVars      map[string]string
		expected     string
		expectedCode int
	}{
		{
			desc: "invalid API key",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected:     "authentication was not successful",
			expectedCode: http.StatusUnauthorized,
		},
		{
			desc: "valid API key",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected:     "",
			expectedCode: http.StatusNoContent,
		},
		{
			desc: "hitting rate limiting",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected:     "rate limited, try again later",
			expectedCode: http.StatusTooManyRequests,
		},
		{
			desc: "server-side error",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected:     "internal server error, try again later",
			expectedCode: http.StatusInternalServerError,
		},
		{
			desc: "authorization error",
			envVars: map[string]string{
				"ACTIVE24_API_KEY": "api-key",
			},
			expected:     "not authorized",
			expectedCode: http.StatusForbidden,
		},
	}

	for _, test := range tt {
		t.Run(test.desc, func(t *testing.T) {
			defer envVals.RestoreEnv()
			envVals.ClearEnv()
			envVals.Apply(test.envVars)

			p := setupFakeDNSProvider(t, test.expectedCode, nil)
			err := p.Present("example.com", "", "foo")
			if len(test.expected) != 0 {
				require.EqualError(t, err, test.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDNSProviderCleanUp(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		expectedCode int
		expected     string
	}{
		// TODO: test cases
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer envVals.RestoreEnv()
			envVals.ClearEnv()
			envVals.Apply(test.envVars)

			p := setupFakeDNSProvider(t, test.expectedCode, nil)
			err := p.CleanUp("example.com", "", "foo")
			if len(test.expected) != 0 {
				require.EqualError(t, err, test.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetDomainHashIds(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		fqdn   string
		body   string
		want   []string
	}{
		{
			name:   "no TXT record with fqdn",
			domain: "example.com",
			fqdn:   "_acme-challenge.example.com.",
			body: `[
			{
			"name": "example.com",
			"ttl": 0,
			"ip": "1.2.3.4",
			"hashId": "abcde",
			"type": "A"
			},
			{
			"name": "text.example.com",
			"ttl": 0,
			"text": "example text",
			"hashId": "qwerty",
			"type": "TXT"
			}
			]
			`,
			want: nil,
		},
		{
			name:   "multiple TXT records matching fqdn",
			domain: "example.com",
			fqdn:   "_acme-challenge.example.com",
			body: `[
			{
			"name": "example.com",
			"ttl": 0,
			"ip": "1.2.3.4",
			"hashId": "abcde",
			"type": "A"
			},
			{
			"name": "_acme-challenge.example.com",
			"ttl": 0,
			"text": "abcd",
			"hashId": "qwerty",
			"type": "TXT"
			},
			{
			"name": "_acme-challenge.example.com",
			"ttl": 0,
			"text": "abcd",
			"hashId": "123456",
			"type": "TXT"
			}
			]
			`,
			want: []string{"qwerty", "123456"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer envVals.RestoreEnv()
			envVals.ClearEnv()
			envVals.Apply(map[string]string{
				EnvApiKey: "api-key",
			})

			p := setupFakeDNSProvider(t, http.StatusOK, []byte(test.body))
			got, err := p.getDomainHashId(test.domain, test.fqdn)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestExtractSecondLvlDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
		errStr string
	}{
		{
			name:   "empty string",
			domain: "",
			want:   "",
			errStr: "can't parse second-level domain",
		},
		{
			name:   "root domain",
			domain: ".",
			want:   "",
			errStr: "can't parse second-level domain",
		},
		{
			name:   "top-level domain",
			domain: ".com",
			want:   "",
			errStr: "can't parse second-level domain",
		},
		{
			name:   "second-level domain",
			domain: "example.com",
			want:   "example.com",
			errStr: "",
		},
		{
			name:   "nested domain",
			domain: "i.am.nested.domain.example.com",
			want:   "example.com",
			errStr: "",
		},
		{
			name:   "non-domain",
			domain: "idonthaveseperator",
			want:   "",
			errStr: "can't parse second-level domain",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := extractSecondLvlDomain(test.domain)
			if len(test.errStr) != 0 {
				require.EqualError(t, err, test.errStr)
			}
			require.Equal(t, test.want, got)
		})
	}
}
