package config

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	str2duration "github.com/xhit/go-str2duration/v2"
	"gopkg.in/yaml.v2"
)



type MongoConfig struct {
	URI            string `yaml:"uri"`
	URIFull         string `yaml:"uri_full"`
	UserCollection string `yaml:"user_collection"`
	DB             string `yaml:"db"`
	Login          string `yaml:"login"`
	Password       string `yaml:"password"`
}

type HTTPConfig struct {
	URI               string `yaml:"uri"`
	AccessCookieName  string `yaml:"access_cookie_name"`
	RefreshCookieName string `yaml:"refresh_cookie_name"`
	APIVersion        string `yaml:"api_version"`
}

type JWTConfig struct {
	Secret           string `yaml:"secret"`
	AccessTTLString  string `yaml:"accessTTL"`
	AccesTTL         time.Duration
	RefreshTTLString string `yaml:"refreshTTL"`
	RefreshTTL       time.Duration
}

type GRPCConfig struct {
	URI       string `yaml:"uri"`
	Transport string `yaml:"transport"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

type Config struct {
	HTTP       HTTPConfig  `yaml:"http_server"`
	GRPC       GRPCConfig  `yaml:"grpc_server"`
	Mongo      MongoConfig `yaml:"mongo"`
	JWT        JWTConfig   `yaml:"jwt"`
	Log        LogConfig   `yaml:"logging"`
}

var once sync.Once
var configG *Config

const (
	defaultConfig = "config/config.yaml"
)

//Parses config ONCE, then just returns ptr to cfg
func NewConfig() *Config {
	var cfgPath, jwtSecret string
	once.Do(func() {
		if c := os.Getenv("CFG_PATH"); c != "" {
			cfgPath = c
		} else {
			log.Println("if you are running localy -> export CFG_PATH=config/config_debug.yaml")
			cfgPath = defaultConfig
			jwtSecret = os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				log.Fatal("config NO JWT SECRET!")
			}
		}
		file, err := os.Open(filepath.Clean(cfgPath))
		if err != nil {
			log.Fatal("config file problem ", err)
		}
		defer file.Close()
		decoder := yaml.NewDecoder(file)
		configG = &Config{}
		err = decoder.Decode(configG)
		if err != nil {
			log.Fatal("config file problem ", err)
		}
		accessDur, err := str2duration.ParseDuration(configG.JWT.AccessTTLString)
		if err != nil {
			log.Fatal("Couldn't parse JWT accessTTL config")
		}
		if accessDur == 0 {
			log.Fatal("accessTokenTTL should be not zero")
		}
		configG.JWT.AccesTTL = accessDur
		refreshDur, err := str2duration.ParseDuration(configG.JWT.RefreshTTLString)
		if err != nil {
			log.Fatal("Couldn't parse JWT refreshTTL config")
		}
		if refreshDur == 0 {
			log.Fatal("refreshTTL should be not zero")
		}
		configG.JWT.RefreshTTL = refreshDur
		if jwtSecret != "" {
			configG.JWT.Secret = jwtSecret
		}
		if configG.JWT.Secret == "" {
			log.Fatal("cfg jwt secret should not be empty")
		}
	})
	return configG
}
