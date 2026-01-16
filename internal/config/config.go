package config

import (
	"fmt"
	"sync"

	"github.com/spf13/viper"
)

type ServerConfig struct {
	Address string `mapstructure:"address"`
	Port    int    `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
}

type DatabaseConfig struct {
	Path    string `mapstructure:"path"`
	LogMode bool   `mapstructure:"log_mode"`
}

type JWTConfig struct {
	Secret      string `mapstructure:"secret"`
	Issuer      string `mapstructure:"issuer"`
	ExpireHours int    `mapstructure:"expire_hours"`
}

type SecurityConfig struct {
	BcryptCost    int    `mapstructure:"bcrypt_cost"`
	EncryptionKey string `mapstructure:"encryption_key"`
}

type LogConfig struct {
	File  string `mapstructure:"file"`
	Level string `mapstructure:"level"`
}

type BackupConfig struct {
	Dir string `mapstructure:"dir"`
}

type AppSubConfig struct {
	PageSize int `mapstructure:"page_size"`
}

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Security SecurityConfig `mapstructure:"security"`
	Log      LogConfig      `mapstructure:"log"`
	Backup   BackupConfig   `mapstructure:"backup"`
	App      AppSubConfig   `mapstructure:"app"`
}

var (
	appConfig *Config
	once      sync.Once
)

// Load loads configuration from given file path (e.g. "config.yaml").
// If path is empty, it defaults to "config.yaml" in current working directory.
func Load(path string) (*Config, error) {
	var err error
	once.Do(func() {
		v := viper.New()

		if path == "" {
			v.SetConfigName("config")
			v.SetConfigType("yaml")
			v.AddConfigPath(".")
		} else {
			v.SetConfigFile(path)
		}

		// environment overrides, e.g. SERVER_PORT=9000
		v.SetEnvPrefix("PPL") // privacy personal ledger
		v.AutomaticEnv()

		if err = v.ReadInConfig(); err != nil {
			err = fmt.Errorf("read config: %w", err)
			return
		}

		var c Config
		if err = v.Unmarshal(&c); err != nil {
			err = fmt.Errorf("unmarshal config: %w", err)
			return
		}

		appConfig = &c
	})

	if err != nil {
		return nil, err
	}
	return appConfig, nil
}

// Get returns the loaded global configuration.
// Call Load() once at application startup.
func Get() *Config {
	return appConfig
}
