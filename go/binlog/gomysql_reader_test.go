package binlog

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/github/gh-ost/go/base"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/stretchr/testify/require"
)

func setUnexportedField(target interface{}, fieldName string, value interface{}) {
	field := reflect.ValueOf(target).Elem().FieldByName(fieldName)
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

func newTestRowsEvent(schemaName, tableName string) *replication.RowsEvent {
	const tableID uint64 = 7

	rowsEvent := &replication.RowsEvent{
		Version: 1,
	}
	setUnexportedField(rowsEvent, "tableIDSize", 6)
	setUnexportedField(rowsEvent, "needBitmap2", false)
	setUnexportedField(rowsEvent, "eventType", replication.WRITE_ROWS_EVENTv1)
	setUnexportedField(rowsEvent, "tables", map[uint64]*replication.TableMapEvent{
		tableID: {
			TableID:     tableID,
			Schema:      []byte(schemaName),
			Table:       []byte(tableName),
			ColumnCount: 1,
			ColumnType:  []byte{gomysql.MYSQL_TYPE_LONG},
			ColumnMeta:  []uint16{0},
			NullBitmap:  []byte{0x00},
		},
	})
	return rowsEvent
}

func newRowsEventDataWithInvalidRowPayload() []byte {
	// RowsEvent v1 header:
	// - 6 byte little-endian table id
	// - 2 byte flags
	// - length-encoded column count = 1
	// - 1 byte column bitmap
	// The final byte is an intentionally truncated row payload. DecodeHeader can
	// parse the table/schema/name, but DecodeData will fail if it is invoked.
	return []byte{7, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
}

func TestRowsEventDecodeFuncSkipsRowDataForFilteredTable(t *testing.T) {
	decodeFunc := newRowsEventDecodeFunc(func(databaseName, tableName string) bool {
		require.Equal(t, "testdb", databaseName)
		require.Equal(t, "ignored_table", tableName)
		return false
	})
	require.NotNil(t, decodeFunc)

	rowsEvent := newTestRowsEvent("testdb", "ignored_table")
	err := decodeFunc(rowsEvent, newRowsEventDataWithInvalidRowPayload())
	require.NoError(t, err)
	require.Equal(t, uint64(7), rowsEvent.TableID)
	require.Equal(t, "testdb", string(rowsEvent.Table.Schema))
	require.Equal(t, "ignored_table", string(rowsEvent.Table.Table))
	require.Empty(t, rowsEvent.Rows)
}

func TestRowsEventDecodeFuncDecodesRowDataForMatchingTable(t *testing.T) {
	decodeFunc := newRowsEventDecodeFunc(func(databaseName, tableName string) bool {
		require.Equal(t, "testdb", databaseName)
		require.Equal(t, "wanted_table", tableName)
		return true
	})
	require.NotNil(t, decodeFunc)

	rowsEvent := newTestRowsEvent("testdb", "wanted_table")
	err := decodeFunc(rowsEvent, newRowsEventDataWithInvalidRowPayload())
	require.Error(t, err)
}

func TestRowsEventDecodeFuncIsNilWithoutFilter(t *testing.T) {
	require.Nil(t, newRowsEventDecodeFunc(nil))
}

func TestIsAuthenticationError(t *testing.T) {
	reader := &GoMySQLReader{migrationContext: base.NewMigrationContext()}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"access denied for user", &gomysql.MyError{Code: errAccessDenied, Message: "Access denied for user 'gh-ost'@'198.51.100.10'"}, true},
		{"host not allowed", &gomysql.MyError{Code: errHostNotAllowed, Message: "Host '198.51.100.10' is not allowed to connect to this MySQL server"}, true},
		{"access denied to database", &gomysql.MyError{Code: errDBAccessDenied, Message: "Access denied for user 'gh-ost'@'%' to database 'mysql'"}, true},
		{"access denied without password", &gomysql.MyError{Code: errAccessDeniedNoPass, Message: "Access denied for user 'root'@'localhost'"}, true},
		{"account locked", &gomysql.MyError{Code: errAccountLocked, Message: "Account has been locked"}, true},
		{"wrapped typed error", fmt.Errorf("connection failed: %w", &gomysql.MyError{Code: errAccessDenied, Message: "Access denied"}), true},
		{"untyped access denied", errors.New("Access denied for user attempting to connect"), true},
		{"untyped authentication failed", errors.New("authentication failed for user"), true},
		{"non-auth typed error", &gomysql.MyError{Code: 1146, Message: "Table doesn't exist"}, false},
		{"connection timeout", errors.New("connection timeout"), false},
		{"connection refused", errors.New("dial tcp: connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, reader.isAuthenticationError(tt.err))
		})
	}
}

func TestHandleAuthErrorTripsAtMaxAuthFailures(t *testing.T) {
	tests := []struct {
		name            string
		maxAuthFailures int
		authFailures    int
		expectTripped   bool
	}{
		{"no limit set", 0, 100, false},
		{"under limit", 5, 3, false},
		{"at limit", 5, 5, true},
		{"over limit", 5, 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrationContext := base.NewMigrationContext()
			migrationContext.MaxAuthFailures = tt.maxAuthFailures
			migrationContext.AuthFailureCount = tt.authFailures - 1

			reader := &GoMySQLReader{migrationContext: migrationContext}

			err := reader.handleAuthError(errors.New("ERROR 1045 (28000): Access denied for user"), "test")

			require.Error(t, err)
			if tt.expectTripped {
				require.ErrorIs(t, err, ErrMaxAuthFailures)
			} else {
				require.NotErrorIs(t, err, ErrMaxAuthFailures)
			}
		})
	}
}

// The streamer discards the binlog reader on every reconnect, so the count has to
// survive on the migration context or the breaker never trips.
func TestHandleAuthErrorPersistsFailuresAcrossReaders(t *testing.T) {
	migrationContext := base.NewMigrationContext()
	migrationContext.MaxAuthFailures = 2
	authErr := errors.New("ERROR 1045 (28000): Access denied for user")

	err := (&GoMySQLReader{migrationContext: migrationContext}).handleAuthError(authErr, "connection")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrMaxAuthFailures)

	err = (&GoMySQLReader{migrationContext: migrationContext}).handleAuthError(authErr, "connection")
	require.ErrorIs(t, err, ErrMaxAuthFailures)
}

func TestHandleAuthErrorCountsOnlyAuthFailures(t *testing.T) {
	migrationContext := base.NewMigrationContext()
	migrationContext.MaxAuthFailures = 10
	reader := &GoMySQLReader{migrationContext: migrationContext}

	tests := []struct {
		name        string
		err         error
		shouldCount bool
	}{
		{"access denied", &gomysql.MyError{Code: errAccessDenied, Message: "Access denied"}, true},
		{"connection timeout", errors.New("connection timeout"), false},
		{"host not allowed", &gomysql.MyError{Code: errHostNotAllowed, Message: "Host not allowed"}, true},
		{"syntax error", errors.New("syntax error"), false},
		{"untyped access denied", errors.New("access denied for user"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := migrationContext.AuthFailureCount
			require.Error(t, reader.handleAuthError(tt.err, "test"))
			if tt.shouldCount {
				require.Equal(t, before+1, migrationContext.AuthFailureCount)
			} else {
				require.Equal(t, before, migrationContext.AuthFailureCount)
			}
		})
	}

	// A success resets the count, so only consecutive failures trip the breaker.
	require.NoError(t, reader.handleAuthError(nil, "test success"))
	require.Zero(t, migrationContext.AuthFailureCount)
}
