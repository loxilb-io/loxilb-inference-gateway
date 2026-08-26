/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
)

const (
	MinPasswordLength      = 9
	TokenExpirationMinutes = 1440 // 24 hours
	CacheExpirationTime    = 5    // 5 minutes
	CacheCleanupInterval   = 10   // 10 minutes
	DefaultLogLimit        = 10   // Default limit for log pagination
	DefaultLogOffset       = 0    // Default offset for log pagination
	MaxRetries             = 5
	RetryDelay             = 2 * time.Second
	DbRetryDelay           = 5 * time.Second
	DbMaxRetries           = 5
	DbRetryBackoff         = 2 * time.Second
	DefaultLicenseExpiry   = 60
)

const (
	SelectAllUsersQuery     = "SELECT id, username, password, created_at, role FROM users"
	SelectUserQuery         = "SELECT id, username, password, role FROM users WHERE id = ?"
	InsertUserQuery         = "INSERT INTO users (username, password, created_at, role) VALUES (?, ?, ?, ?)"
	UpdateUserQuery         = "UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?"
	DeleteUserQuery         = "DELETE FROM users WHERE id = ?"
	SelectUserPasswordQuery = "SELECT password, role FROM users WHERE username = ?"
	InsertTokenQuery        = "INSERT INTO token (token_value, username, expires_at, role) VALUES (?, ?, ?, ?)"
	ValidateTokenQuery      = "SELECT username,role FROM token WHERE token_value = ? AND expires_at > NOW()"
	DeleteTokenQuery        = "DELETE FROM token WHERE token_value = ?"
	DeleteExpiredTokenQuery = "DELETE FROM token WHERE expires_at < NOW()"

	CreateAPIKeysTableQuery = `CREATE TABLE IF NOT EXISTS api_keys (` +
		`key_id VARCHAR(64) PRIMARY KEY,` +
		`key_hash VARCHAR(64) NOT NULL,` +
		`tenant_id VARCHAR(128) NOT NULL,` +
		`name VARCHAR(255) NOT NULL DEFAULT '',` +
		`allowed_models TEXT NOT NULL,` +
		`rate_limit_rps INT DEFAULT 0,` +
		`burst_size INT DEFAULT 0,` +
		`tokens_per_min INT DEFAULT 0,` +
		`created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),` +
		`expires_at DATETIME(3) NULL,` +
		`enabled TINYINT(1) NOT NULL DEFAULT 1,` +
		`INDEX idx_tenant_id (tenant_id)` +
		`) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

	CreateTenantRateLimitsTableQuery = `CREATE TABLE IF NOT EXISTS tenant_rate_limits (` +
		`tenant_id VARCHAR(128) PRIMARY KEY,` +
		`rps INT NOT NULL DEFAULT 0,` +
		`tokens_per_min INT NOT NULL DEFAULT 0,` +
		`burst_pct INT NOT NULL DEFAULT 0,` +
		`updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)` +
		`) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

	// AlterTenantRateLimitsAddBurstQuery back-fills burst_pct on a
	// tenant_rate_limits table created before the column existed. There is no
	// migration framework here and CREATE TABLE IF NOT EXISTS leaves an
	// existing table alone, so without this an upgraded deployment keeps the
	// old four-column table and every statement naming burst_pct fails —
	// taking the whole tenant rate-limit plane down, not just the new knob.
	// MySQL has no ADD COLUMN IF NOT EXISTS, so the duplicate-column error is
	// the already-migrated case and is tolerated rather than avoided.
	AlterTenantRateLimitsAddBurstQuery = `ALTER TABLE tenant_rate_limits ADD COLUMN burst_pct INT NOT NULL DEFAULT 0`

	CreateTenantModelRateLimitsTableQuery = `CREATE TABLE IF NOT EXISTS tenant_model_rate_limits (` +
		`tenant_id VARCHAR(128) NOT NULL,` +
		`model VARCHAR(255) NOT NULL,` +
		`tokens_per_min INT NOT NULL DEFAULT 0,` +
		`updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),` +
		`PRIMARY KEY (tenant_id, model)` +
		`) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

	CreateUsersTableQuery = `CREATE TABLE IF NOT EXISTS users (` +
		`id INT AUTO_INCREMENT PRIMARY KEY,` +
		`username VARCHAR(255) NOT NULL,` +
		`password VARCHAR(255) NOT NULL,` +
		`created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,` +
		`role VARCHAR(255) NOT NULL DEFAULT 'viewer'` +
		`) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

	CreateTokenTableQuery = `CREATE TABLE IF NOT EXISTS token (` +
		`id INT AUTO_INCREMENT PRIMARY KEY,` +
		`token_value VARCHAR(512) NOT NULL,` +
		`username VARCHAR(255) NOT NULL,` +
		`expires_at TIMESTAMP NOT NULL,` +
		`created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,` +
		`role VARCHAR(255) NOT NULL` +
		`) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
)

func InitDB() (*sql.DB, error) {
	var err error
	bytePassword, err := os.ReadFile(options.Opts.DatabasePasswordPath)
	if err != nil {
		tk.LogIt(tk.LogCritical, "Failed to read password file: %v\n", err)
		return nil, err
	}
	rawPassword := string(bytePassword)
	Password := strings.TrimSpace(rawPassword)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		options.Opts.DatabaseUser,
		Password,
		options.Opts.DatabaseHost,
		options.Opts.DatabasePort,
		options.Opts.DatabaseName,
	)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		tk.LogIt(tk.LogCritical, "Error opening database: %v\n", err)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		tk.LogIt(tk.LogCritical, "Error connecting to the database: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(CreateUsersTableQuery); err != nil {
		tk.LogIt(tk.LogCritical, "Failed to create users table: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(CreateTokenTableQuery); err != nil {
		tk.LogIt(tk.LogCritical, "Failed to create token table: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(CreateAPIKeysTableQuery); err != nil {
		tk.LogIt(tk.LogCritical, "Failed to create api_keys table: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(CreateTenantRateLimitsTableQuery); err != nil {
		tk.LogIt(tk.LogCritical, "Failed to create tenant_rate_limits table: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(AlterTenantRateLimitsAddBurstQuery); err != nil && !IsDuplicateColumnError(err) {
		tk.LogIt(tk.LogCritical, "Failed to add tenant_rate_limits.burst_pct: %v\n", err)
		return nil, err
	}
	if _, err = db.Exec(CreateTenantModelRateLimitsTableQuery); err != nil {
		tk.LogIt(tk.LogCritical, "Failed to create tenant_model_rate_limits table: %v\n", err)
		return nil, err
	}
	return db, nil
}

// IsDuplicateColumnError reports MySQL error 1060 (duplicate column name),
// which an idempotent ALTER TABLE ... ADD COLUMN returns when the column is
// already present. That is the success case on an already-migrated database,
// not a failure.
func IsDuplicateColumnError(err error) bool {
	if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1060 {
		return true
	}
	return false
}

func IsDuplicateEntryError(err error) bool {
	// Check if the error is a MySQL duplicate entry error
	if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
		return true
	}
	return false
}

func ConnectWithRetry(maxRetries int, retryDelay time.Duration) (*sql.DB, error) {
	var db *sql.DB
	var err error
	bytePassword, err := os.ReadFile(options.Opts.DatabasePasswordPath)
	if err != nil {
		tk.LogIt(tk.LogCritical, "Failed to read password file: %v\n", err)
		return nil, err
	}
	rawPassword := string(bytePassword)
	Password := strings.TrimSpace(rawPassword)
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		options.Opts.DatabaseUser,
		Password,
		options.Opts.DatabaseHost,
		options.Opts.DatabasePort,
		options.Opts.DatabaseName,
	)
	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("mysql", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := db.PingContext(ctx); err == nil {
				return db, nil
			} else if i == maxRetries-1 {
				tk.LogIt(tk.LogCritical, "Failed to reconnect to the database: %v\n", err)
				return nil, err
			}
		}
		time.Sleep(retryDelay)
	}
	return nil, err
}
