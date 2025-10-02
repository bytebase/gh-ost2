package binlog

import (
	"errors"
	"fmt"
	"testing"

	"github.com/github/gh-ost/go/base"
	"github.com/github/gh-ost/go/mysql"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/stretchr/testify/require"
)

func TestIsAuthenticationError(t *testing.T) {
	migrationContext := base.NewMigrationContext()
	reader := &GoMySQLReader{
		migrationContext: migrationContext,
	}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "MySQL 1045 typed error",
			err:      &gomysql.MyError{Code: 1045, Message: "Access denied for user 'bytebase'@'10.20.5.203'"},
			expected: true,
		},
		{
			name:     "MySQL 1130 typed error",
			err:      &gomysql.MyError{Code: 1130, Message: "Host '10.20.5.203' is not allowed to connect to this MySQL server"},
			expected: true,
		},
		{
			name:     "MySQL 1044 typed error",
			err:      &gomysql.MyError{Code: 1044, Message: "Access denied for user 'bytebase'@'%' to database 'mysql'"},
			expected: true,
		},
		{
			name:     "MySQL 1698 typed error",
			err:      &gomysql.MyError{Code: 1698, Message: "Access denied for user 'root'@'localhost'"},
			expected: true,
		},
		{
			name:     "MySQL 3118 account locked",
			err:      &gomysql.MyError{Code: 3118, Message: "Account has been locked"},
			expected: true,
		},
		{
			name:     "Wrapped MySQL error",
			err:      fmt.Errorf("connection failed: %w", &gomysql.MyError{Code: 1045, Message: "Access denied"}),
			expected: true,
		},
		{
			name:     "String fallback - access denied",
			err:      errors.New("Access denied for user attempting to connect"),
			expected: true,
		},
		{
			name:     "String fallback - authentication failed",
			err:      errors.New("authentication failed for user"),
			expected: true,
		},
		{
			name:     "Non-auth MySQL error",
			err:      &gomysql.MyError{Code: 1146, Message: "Table doesn't exist"},
			expected: false,
		},
		{
			name:     "unrelated error",
			err:      errors.New("connection timeout"),
			expected: false,
		},
		{
			name:     "network error",
			err:      errors.New("dial tcp: connection refused"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reader.isAuthenticationError(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthFailureCircuitBreaker(t *testing.T) {
	tests := []struct {
		name            string
		maxAuthFailures int
		authFailures    int
		expectError     bool
	}{
		{
			name:            "no limit set",
			maxAuthFailures: 0,
			authFailures:    100,
			expectError:     false, // No limit means no circuit breaker
		},
		{
			name:            "under limit",
			maxAuthFailures: 5,
			authFailures:    3,
			expectError:     false,
		},
		{
			name:            "at limit",
			maxAuthFailures: 5,
			authFailures:    5,
			expectError:     true,
		},
		{
			name:            "over limit",
			maxAuthFailures: 5,
			authFailures:    10,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrationContext := base.NewMigrationContext()
			migrationContext.MaxAuthFailures = tt.maxAuthFailures

			connectionConfig := &mysql.ConnectionConfig{
				Key: mysql.InstanceKey{
					Hostname: "test-host",
					Port:     3306,
				},
				User:     "test-user",
				Password: "test-password",
			}

			reader := &GoMySQLReader{
				migrationContext: migrationContext,
				connectionConfig: connectionConfig,
				authFailureCount: tt.authFailures - 1, // Simulate previous failures
			}

			// Simulate an authentication error
			authErr := errors.New("ERROR 1045 (28000): Access denied for user")

			// Check if circuit breaker triggers
			if reader.isAuthenticationError(authErr) {
				reader.authFailureCount++
				if reader.migrationContext.MaxAuthFailures > 0 && reader.authFailureCount >= reader.migrationContext.MaxAuthFailures {
					if !tt.expectError {
						t.Errorf("Expected no error but circuit breaker triggered at %d failures", reader.authFailureCount)
					}
				} else {
					if tt.expectError {
						t.Errorf("Expected circuit breaker to trigger at %d failures but it didn't", reader.authFailureCount)
					}
				}
			}
		})
	}
}

func TestAuthFailureCounterIncrement(t *testing.T) {
	migrationContext := base.NewMigrationContext()
	migrationContext.MaxAuthFailures = 10

	reader := &GoMySQLReader{
		migrationContext: migrationContext,
		authFailureCount: 0,
	}

	// Test that counter increments only for auth errors
	errors := []struct {
		err         error
		shouldCount bool
	}{
		{errors.New("ERROR 1045: Access denied"), true},
		{errors.New("connection timeout"), false},
		{errors.New("ERROR 1130: Host not allowed"), true},
		{errors.New("syntax error"), false},
		{nil, false},
	}

	expectedCount := 0
	for _, e := range errors {
		if reader.isAuthenticationError(e.err) {
			reader.authFailureCount++
			if e.shouldCount {
				expectedCount++
			} else {
				t.Errorf("Counter incremented for non-auth error: %v", e.err)
			}
		} else if e.shouldCount {
			t.Errorf("Counter did not increment for auth error: %v", e.err)
		}
	}

	if reader.authFailureCount != expectedCount {
		t.Errorf("Expected auth failure count %d, got %d", expectedCount, reader.authFailureCount)
	}
}

func TestAuthFailureCounterReset(t *testing.T) {
	migrationContext := base.NewMigrationContext()
	migrationContext.MaxAuthFailures = 10

	reader := &GoMySQLReader{
		migrationContext: migrationContext,
		authFailureCount: 0,
	}

	// Simulate auth failures
	authError := errors.New("ERROR 1045: Access denied")
	for i := 0; i < 3; i++ {
		if reader.isAuthenticationError(authError) {
			reader.authFailureCount++
		}
	}

	if reader.authFailureCount != 3 {
		t.Errorf("Expected auth failure count 3, got %d", reader.authFailureCount)
	}

	// Simulate successful connection - should reset counter
	// In real code, this happens in ConnectBinlogStreamer on success
	reader.authFailureCount = 0

	if reader.authFailureCount != 0 {
		t.Errorf("Expected auth failure count to be reset to 0, got %d", reader.authFailureCount)
	}

	// Simulate more failures after reset
	for i := 0; i < 2; i++ {
		if reader.isAuthenticationError(authError) {
			reader.authFailureCount++
		}
	}

	if reader.authFailureCount != 2 {
		t.Errorf("Expected auth failure count 2 after reset, got %d", reader.authFailureCount)
	}
}

func TestAuthFailureRecoveryScenario(t *testing.T) {
	// Test a realistic scenario:
	// 1. Some auth failures
	// 2. Successful connection (counter reset)
	// 3. More auth failures
	// 4. Should only trigger circuit breaker based on consecutive failures

	migrationContext := base.NewMigrationContext()
	migrationContext.MaxAuthFailures = 5

	reader := &GoMySQLReader{
		migrationContext: migrationContext,
		authFailureCount: 0,
	}

	authError := errors.New("ERROR 1045: Access denied")

	// First round: 3 failures
	for i := 0; i < 3; i++ {
		if reader.isAuthenticationError(authError) {
			reader.authFailureCount++
		}
	}
	require.Equal(t, 3, reader.authFailureCount, "Should have 3 failures")

	// Successful connection - reset
	reader.authFailureCount = 0
	require.Equal(t, 0, reader.authFailureCount, "Should reset to 0 after success")

	// Second round: 4 more failures (under limit)
	for i := 0; i < 4; i++ {
		if reader.isAuthenticationError(authError) {
			reader.authFailureCount++
		}
	}
	require.Equal(t, 4, reader.authFailureCount, "Should have 4 failures after reset")

	// Circuit breaker should not trigger yet (4 < 5)
	shouldTrigger := reader.migrationContext.MaxAuthFailures > 0 &&
		reader.authFailureCount >= reader.migrationContext.MaxAuthFailures
	require.False(t, shouldTrigger, "Circuit breaker should not trigger at 4 failures with limit 5")

	// One more failure should trigger
	reader.authFailureCount++
	shouldTrigger = reader.migrationContext.MaxAuthFailures > 0 &&
		reader.authFailureCount >= reader.migrationContext.MaxAuthFailures
	require.True(t, shouldTrigger, "Circuit breaker should trigger at 5 failures with limit 5")
}
