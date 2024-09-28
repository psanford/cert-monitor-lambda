package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

func main() {
	s := newServer()
	lambda.Start(s.Handler)
}

func newServer() *server {
	return &server{}
}

type server struct {
	bucket   string
	s3       *s3.Client
	conf     *Config
	patterns []*regexp.Regexp
}

func (s *server) Handler(evt events.CloudWatchEvent) error {
	lgr := slog.With()
	ctx := context.Background()

	bucketName := os.Getenv("CERT_MONITOR_BUCKET")
	if bucketName == "" {
		return errors.New("environment var CERT_MONITOR_BUCKET not set")
	}

	s.bucket = bucketName

	// create an aws sdk v2 go
	cfg, err := config.LoadDefaultConfig(ctx, config.WithDisableRequestCompression(aws.Bool(true)))
	if err != nil {
		return err
	}
	s3client := s3.NewFromConfig(cfg)

	s.s3 = s3client

	confResult := make(chan *Config)
	stateResult := make(chan LogStates)
	logListResult := make(chan *loglist3.LogList)
	errorChan := make(chan error)

	go func() {
		conf, err := s.loadConfig(ctx)
		if err != nil {
			errorChan <- fmt.Errorf("load config err: %w", err)
		}
		confResult <- conf
	}()

	go func() {
		states, err := s.fetchLogState(ctx)
		if err != nil {
			lgr.Error("warning no existing log states found", "fetch error", err)
			states = make(LogStates)
		}
		stateResult <- states
	}()

	go func() {
		list, err := fetchLogList()
		if err != nil {
			errorChan <- fmt.Errorf("fetch log list err: %w", err)
		}
		logListResult <- list
	}()

	var (
		states  LogStates
		logList *loglist3.LogList
	)

	for i := 0; i < 3; i++ {
		select {
		case s.conf = <-confResult:
		case states = <-stateResult:
		case logList = <-logListResult:
		case err := <-errorChan:
			return err
		}
	}

	patterns := make([]*regexp.Regexp, len(s.conf.Patterns))
	for i, patternStr := range s.conf.Patterns {
		r, err := regexp.Compile(patternStr)
		if err != nil {
			return fmt.Errorf("error compiling regex pattern %s err=%s", patternStr, err)
		}
		patterns[i] = r
	}

	s.patterns = patterns

	resultChan := make(chan *LogState)
	var logCount int

	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if log.State.LogStatus() != loglist3.UsableLogStatus {
				continue
			}

			state := states[log.URL]
			if state == nil {
				state = &LogState{
					URL:         log.URL,
					Operator:    operator.Name,
					Description: log.Description,
				}
			}

			logCount++
			go func() {
				result, err := s.processLog(ctx, lgr, state)
				if err != nil {
					errorChan <- err
				} else {
					resultChan <- result
				}
			}()
		}
	}

	lgr.Info("waiting for results", "log_count", logCount)

	for i := 0; i < logCount; i++ {
		select {
		case state := <-resultChan:
			lgr.Info("got state result", "url", state.URL, "i", i)
			states[state.URL] = state
		case err := <-errorChan:
			lgr.Error("got fatal client error", "err", err)
			return err
		}
	}

	statesTxt, err := json.Marshal(states)
	if err != nil {
		return fmt.Errorf("marshal states err: %w", err)
	}

	_, err = s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    &logStateKey,
		Body:   bytes.NewBuffer(statesTxt),
	})
	if err != nil {
		return fmt.Errorf("put state file err %w", err)
	}

	return nil
}

func (s *server) processLog(ctx context.Context, lgr *slog.Logger, state *LogState) (*LogState, error) {
	lgr = lgr.With("log", state.URL)
	lgr.Info("fetch log")
	var entriesSeen int
	defer func() {
		lgr.Info("fetch log done", "entry_count", entriesSeen)
	}()
	lc, err := client.New(state.URL, http.DefaultClient, jsonclient.Options{})
	if err != nil {
		lgr.Error("new client err", "err", err)
		return nil, err
	}

	sth, err := lc.GetSTH(ctx)
	if err != nil {
		lgr.Error("fetch sth error", "err", err)
		return state, nil
	}

	if state.LastFetched == 0 {
		lgr.Info("init state")
		state.LastFetched = sth.TreeSize
		state.LastFetchedTime = time.Now()
		return state, nil
	}

	if sth.TreeSize == state.LastFetched {
		lgr.Info("log not changed")
		return state, nil
	}

	start := int64(state.LastFetched + 1)
	rawEntries, err := lc.GetRawEntries(ctx, start, int64(sth.TreeSize))
	if err != nil {
		lgr.Error("get raw entries err", "err", err)
		return state, nil
	}

	for i, entry := range rawEntries.Entries {
		entriesSeen++
		index := start + int64(i)
		logEntry, err := ct.LogEntryFromLeaf(index, &entry)
		if x509.IsFatal(err) {
			lgr.Error("get parse log err", "err", err)
			continue
		}

		certType := "cert"
		var cert *x509.Certificate
		if logEntry.X509Cert != nil {
			cert = logEntry.X509Cert
		}

		if s.conf.IncludePreCerts && logEntry.Precert != nil {
			certType = "precert"
			cert = logEntry.Precert.TBSCertificate
		}

		if cert != nil {
			if match, name, matchStr := s.nameMatches(cert); match {
				b := make([]byte, 16)
				rand.Read(b)
				bstr := base64.URLEncoding.EncodeToString(b)
				key := fmt.Sprintf("certs/%s-%s-%s.json", time.Now().Format(time.RFC3339Nano), bstr, name)
				lgr.Info("match", "type", certType, "rule", matchStr, "name", name, "key", key)

				jsonTxt, err := json.Marshal(entry)
				if err != nil {
					lgr.Error("marshal json err", "key", key, "err", err)
					return nil, err
				}

				_, err = s.s3.PutObject(ctx, &s3.PutObjectInput{
					Bucket: &s.bucket,
					Key:    &key,
					Body:   bytes.NewBuffer(jsonTxt),
				})
				if err != nil {
					lgr.Error("put cert err", "key", key, "err", err)
					return nil, fmt.Errorf("s3 put object err: %w", err)
				}
			}
		}
	}

	state.LastFetched = sth.TreeSize
	state.LastFetchedTime = time.Now()
	return state, nil
}

func (s *server) nameMatches(c *x509.Certificate) (bool, string, string) {
	for _, name := range c.DNSNames {
		for _, lookingFor := range s.conf.Domains {
			if strings.HasSuffix(name, lookingFor) {
				if name == lookingFor || strings.HasSuffix(name, "."+lookingFor) {
					return true, name, fmt.Sprintf("domain-%s", lookingFor)
				}
			}
		}
		for _, pattern := range s.patterns {
			if pattern.Match([]byte(name)) {
				return true, name, fmt.Sprintf("pattern-%s", pattern)
			}
		}
	}

	return false, "", ""

}

type LogStates map[string]*LogState

var logStateKey = "log-state.json"

func (s *server) fetchLogState(ctx context.Context) (LogStates, error) {
	resp, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &logStateKey,
	})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result map[string]*LogState
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type LogState struct {
	URL             string    `json:"url"`
	Operator        string    `json:"operator"`
	Description     string    `json:"description"`
	LastFetched     uint64    `json:"last_fetched"`
	LastFetchedTime time.Time `json:"last_fetched_time"`
}

func fetchLogList() (*loglist3.LogList, error) {
	req, err := http.Get(loglist3.LogListURL)
	if err != nil {
		return nil, fmt.Errorf("fetch log list err: %s", err)
	}

	llData, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	logList, err := loglist3.NewFromJSON(llData)
	if err != nil {
		return nil, err
	}

	return logList, nil
}
