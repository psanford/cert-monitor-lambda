package main

import (
	"context"
	"io"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	// list of domains to monitor, including subdomains
	// "example.com" will match `example.com` and `foo.example.com`
	Domains []string `toml:"domains"`

	// list of regular expression patterns to match on
	Patterns []string `toml:"patterns"`

	// Coollect pre-certificate entries
	IncludePreCerts bool `toml:"include_pre_certs"`
}

func (s *server) loadConfig(ctx context.Context) (*Config, error) {
	resp, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    aws.String("cert-monitor.toml"),
	})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var conf Config
	err = toml.Unmarshal(body, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}
