package main

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

const (
	CONFIGFILENAME = "config"
	CONFIGFILETYPE = "yaml"
	CONFIGFILEPATH = "./"
)

type Common struct {
}

type Storage struct {
	DDBAWSRegion                string `mapstructure:"DDBAWSRegion"`
	DDBTableName                string `mapstructure:"DDBTableName"`
	GSIPosixIDIndexName         string `mapstructure:"GSIPosixIDIndexName"`
	GSIUUIDIndexName            string `mapstructure:"GSIUUIDIndexName"`
	GSISecondaryGroupsIndexName string `mapstructure:"GSISecondaryGroupsIndexName"`
	GSINameIndexName            string `mapstructure:"GSINameIndexName"`
	GSIEmailIndexName           string `mapstructure:"GSIEmailIndexName"`
	GsiTypeIndexName            string `mapstructure:"GsiTypeIndexName"`
}

type AwsSecret struct {
	SecretEntry  string `mapstructure:"SecretEntry"`
	SecretRegion string `mapstructure:"SecretRegion"`
}

type Caserver struct {
	HostCertSignerKey   AwsSecret `mapstructure:"HostCertSignerKey"`
	UserCertSignerKey   AwsSecret `mapstructure:"UserCertSignerKey"`
	CertMaxValidityDays int       `mapstructure:"CertMaxValidityDays"`
}

type OauthConfig struct {
	ClientID                     string    `mapstructure:"ClientID"`
	ClientSecret                 AwsSecret `mapstructure:"ClientSecret"`
	Scopes                       []string  `mapstructure:"Scopes"`
	OauthCallBackHandlerPath     string    `mapstructure:"OauthCallBackHandlerPath"`
	OauthStateParamName          string    `mapstructure:"OauthStateParamName"`
	OauthClaimsEntitlementsField string    `mapstructure:"OauthClaimsEntitlementsField"`
	OauthEndPoint                string    `mapstructure:"OauthEndPoint"`
	OIDCIssuerURL                string    `mapstructure:"OIDCIssuerURL"`
	OauthEndPointAuthURL         string    `mapstructure:"OauthEndPointAuthURL"`
	OauthEndPointTokenURL        string    `mapstructure:"OauthEndPointTokenURL"`
}

type APIKeyCred struct {
	ApiKeyID     string    `mapstructure:"ApiKeyID"`
	ApiKeySecret AwsSecret `mapstructure:"ApiKeySecret"`
}

type Httpserver struct {
	Addr                        string       `mapstructure:"Addr"`
	OauthConfig                 OauthConfig  `mapstructure:"OauthConfig"`
	APIKeyCreds                 []APIKeyCred `mapstructure:"APIKeyCreds"`
	ApiKeySignatureValiditySecs int          `mapstructure:"ApiKeySignatureValiditySecs"`
	ApiKeyAuthzReqHeader        string       `mapstructure:"ApiKeyAuthzReqHeader"`
	CookieKey                   string       `mapstructure:"CookieKey"`
	CookieSecret                AwsSecret    `mapstructure:"CookieSecret"`
	AdminUserClaimsMatches      []string     `mapstructure:"AdminUserClaimsMatches"`
	AdminHomeTmplName           string       `mapstructure:"AdminHomeTmplName"`
	HomeTmplName                string       `mapstructure:"HomeTmplName"`
}

type SwoosshCfg struct {
	Stage         Stage
	Common        Common     `mapstructure:"Common"`
	Storage       Storage    `mapstructure:"Storage"`
	CAServer      Caserver   `mapstructure:"CAServer"`
	HttpServer    Httpserver `mapstructure:"HTTPServer"`
	LogFilePrefix string     `mapstructure:"LogFilePrefix"`
	LogPrefix     string     `mapstructure:"LogPrefix"`
}

type Stage int

const (
	DEV Stage = iota
	PROD
	UNIDENTIFIED
)

func (d Stage) String() string {
	return [...]string{"DEV", "PROD"}[d]
}

func StageOut(stage string) (Stage, error) {
	switch stage {
	case "dev":
		return DEV, nil
	case "prod":
		return PROD, nil
	default:
		return UNIDENTIFIED, errors.New("Incorrect stage string passed")
	}
}

func configParser(stage Stage) (*SwoosshCfg, error) {
	cfg := viper.New()
	cfg.SetConfigName(CONFIGFILENAME)
	cfg.SetConfigType(CONFIGFILETYPE)
	cfg.AddConfigPath(CONFIGFILEPATH)
	err := cfg.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to read the configuration file - %+v", err)
	}
	swoosshCfg := &SwoosshCfg{}
	err = cfg.Sub(stage.String()).Unmarshal(swoosshCfg)
	if err != nil {
		return nil, fmt.Errorf("Unmarshalling the supplied configuration failed - %+v", err)
	}
	return swoosshCfg, nil
}
