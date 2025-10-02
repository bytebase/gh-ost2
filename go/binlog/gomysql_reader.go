/*
   Copyright 2022 GitHub Inc.
	 See https://github.com/github/gh-ost/blob/master/LICENSE
*/

package binlog

import (
	"fmt"
	"strings"
	"sync"

	"github.com/github/gh-ost/go/base"
	"github.com/github/gh-ost/go/mysql"
	"github.com/github/gh-ost/go/sql"
	"github.com/pkg/errors"

	"time"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"golang.org/x/net/context"
)

type GoMySQLReader struct {
	migrationContext         *base.MigrationContext
	connectionConfig         *mysql.ConnectionConfig
	binlogSyncer             *replication.BinlogSyncer
	binlogStreamer           *replication.BinlogStreamer
	currentCoordinates       mysql.BinlogCoordinates
	currentCoordinatesMutex  *sync.Mutex
	LastAppliedRowsEventHint mysql.BinlogCoordinates
	authFailureCount         int
}

func NewGoMySQLReader(migrationContext *base.MigrationContext) *GoMySQLReader {
	connectionConfig := migrationContext.InspectorConnectionConfig
	return &GoMySQLReader{
		migrationContext:        migrationContext,
		connectionConfig:        connectionConfig,
		currentCoordinates:      mysql.BinlogCoordinates{},
		currentCoordinatesMutex: &sync.Mutex{},
		binlogSyncer: replication.NewBinlogSyncer(replication.BinlogSyncerConfig{
			ServerID:                uint32(migrationContext.ReplicaServerId),
			Flavor:                  gomysql.MySQLFlavor,
			Host:                    connectionConfig.Key.Hostname,
			Port:                    uint16(connectionConfig.Key.Port),
			User:                    connectionConfig.User,
			Password:                connectionConfig.Password,
			TLSConfig:               connectionConfig.TLSConfig(),
			UseDecimal:              true,
			MaxReconnectAttempts:    migrationContext.BinlogSyncerMaxReconnectAttempts,
			TimestampStringLocation: time.UTC,
		}),
	}
}

// handleAuthError processes authentication errors and applies circuit breaker logic
func (this *GoMySQLReader) handleAuthError(err error, context string) error {
	if err == nil {
		// Success case - reset counter if needed
		if this.authFailureCount > 0 {
			this.migrationContext.Log.Infof("%s successful, resetting auth failure count from %d to 0", context, this.authFailureCount)
			this.authFailureCount = 0
		}
		return nil
	}

	// Check if this is an authentication error
	if !this.isAuthenticationError(err) {
		return err // Not an auth error, return as-is
	}

	// Authentication error - increment counter and check circuit breaker
	this.authFailureCount++

	if this.migrationContext.MaxAuthFailures > 0 && this.authFailureCount >= this.migrationContext.MaxAuthFailures {
		return fmt.Errorf("authentication failed %d times (max: %d) during %s, aborting to prevent firewall blocking: %w",
			this.authFailureCount, this.migrationContext.MaxAuthFailures, context, err)
	}

	this.migrationContext.Log.Errorf("Authentication failure #%d during %s (max: %d): %v",
		this.authFailureCount, context, this.migrationContext.MaxAuthFailures, err)

	return err
}

// ConnectBinlogStreamer
func (this *GoMySQLReader) ConnectBinlogStreamer(coordinates mysql.BinlogCoordinates) (err error) {
	if coordinates.IsEmpty() {
		return this.migrationContext.Log.Errorf("Empty coordinates at ConnectBinlogStreamer()")
	}

	this.currentCoordinates = coordinates
	this.migrationContext.Log.Infof("Connecting binlog streamer at %+v", this.currentCoordinates)
	// Start sync with specified binlog file and position
	this.binlogStreamer, err = this.binlogSyncer.StartSync(gomysql.Position{
		Name: this.currentCoordinates.LogFile,
		Pos:  uint32(this.currentCoordinates.LogPos),
	})

	// Handle the error (or success) with circuit breaker logic
	return this.handleAuthError(err, "connection")
}

func (this *GoMySQLReader) GetCurrentBinlogCoordinates() *mysql.BinlogCoordinates {
	this.currentCoordinatesMutex.Lock()
	defer this.currentCoordinatesMutex.Unlock()
	returnCoordinates := this.currentCoordinates
	return &returnCoordinates
}

// StreamEvents
func (this *GoMySQLReader) handleRowsEvent(ev *replication.BinlogEvent, rowsEvent *replication.RowsEvent, entriesChannel chan<- *BinlogEntry) error {
	if this.currentCoordinates.IsLogPosOverflowBeyond4Bytes(&this.LastAppliedRowsEventHint) {
		return fmt.Errorf("Unexpected rows event at %+v, the binlog end_log_pos is overflow 4 bytes", this.currentCoordinates)
	}

	if this.currentCoordinates.SmallerThanOrEquals(&this.LastAppliedRowsEventHint) {
		this.migrationContext.Log.Debugf("Skipping handled query at %+v", this.currentCoordinates)
		return nil
	}

	dml := ToEventDML(ev.Header.EventType.String())
	if dml == NotDML {
		return fmt.Errorf("Unknown DML type: %s", ev.Header.EventType.String())
	}
	for i, row := range rowsEvent.Rows {
		if dml == UpdateDML && i%2 == 1 {
			// An update has two rows (WHERE+SET)
			// We do both at the same time
			continue
		}
		binlogEntry := NewBinlogEntryAt(this.currentCoordinates)
		binlogEntry.DmlEvent = NewBinlogDMLEvent(
			string(rowsEvent.Table.Schema),
			string(rowsEvent.Table.Table),
			dml,
		)
		switch dml {
		case InsertDML:
			{
				binlogEntry.DmlEvent.NewColumnValues = sql.ToColumnValues(row)
			}
		case UpdateDML:
			{
				binlogEntry.DmlEvent.WhereColumnValues = sql.ToColumnValues(row)
				binlogEntry.DmlEvent.NewColumnValues = sql.ToColumnValues(rowsEvent.Rows[i+1])
			}
		case DeleteDML:
			{
				binlogEntry.DmlEvent.WhereColumnValues = sql.ToColumnValues(row)
			}
		}
		// The channel will do the throttling. Whoever is reading from the channel
		// decides whether action is taken synchronously (meaning we wait before
		// next iteration) or asynchronously (we keep pushing more events)
		// In reality, reads will be synchronous
		entriesChannel <- binlogEntry
	}
	this.LastAppliedRowsEventHint = this.currentCoordinates
	return nil
}

// StreamEvents
func (this *GoMySQLReader) StreamEvents(canStopStreaming func() bool, entriesChannel chan<- *BinlogEntry) error {
	if canStopStreaming() {
		return nil
	}
	for {
		if canStopStreaming() {
			break
		}
		ev, err := this.binlogStreamer.GetEvent(context.Background())
		if err != nil {
			// Handle authentication errors with circuit breaker
			return this.handleAuthError(err, "streaming")
		}

		// Reset counter on successful event (using handleAuthError with nil)
		this.handleAuthError(nil, "event retrieval")

		func() {
			this.currentCoordinatesMutex.Lock()
			defer this.currentCoordinatesMutex.Unlock()
			this.currentCoordinates.LogPos = int64(ev.Header.LogPos)
			this.currentCoordinates.EventSize = int64(ev.Header.EventSize)
		}()

		switch binlogEvent := ev.Event.(type) {
		case *replication.RotateEvent:
			func() {
				this.currentCoordinatesMutex.Lock()
				defer this.currentCoordinatesMutex.Unlock()
				this.currentCoordinates.LogFile = string(binlogEvent.NextLogName)
			}()
			this.migrationContext.Log.Infof("rotate to next log from %s:%d to %s", this.currentCoordinates.LogFile, int64(ev.Header.LogPos), binlogEvent.NextLogName)
		case *replication.RowsEvent:
			if err := this.handleRowsEvent(ev, binlogEvent, entriesChannel); err != nil {
				return err
			}
		}
	}
	this.migrationContext.Log.Debugf("done streaming events")

	return nil
}

func (this *GoMySQLReader) Close() error {
	this.binlogSyncer.Close()
	return nil
}

// MySQL error codes for authentication failures
const (
	ER_DBACCESS_DENIED_ERROR     = 1044 // Access denied for user to database
	ER_ACCESS_DENIED_ERROR       = 1045 // Access denied for user (using password: YES/NO)
	ER_HOST_NOT_ALLOWED          = 1130 // Host is not allowed to connect
	ER_ACCESS_DENIED_NO_PASSWORD = 1698 // Access denied (no password provided)
	ER_ACCOUNT_HAS_BEEN_LOCKED   = 3118 // Account has been locked
)

// isAuthenticationError checks if the error is an authentication failure
func (this *GoMySQLReader) isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	// Check for MySQL protocol errors using proper type assertion
	var myErr *gomysql.MyError
	if errors.As(err, &myErr) {
		switch myErr.Code {
		case ER_ACCESS_DENIED_ERROR,
			ER_DBACCESS_DENIED_ERROR,
			ER_HOST_NOT_ALLOWED,
			ER_ACCESS_DENIED_NO_PASSWORD,
			ER_ACCOUNT_HAS_BEEN_LOCKED:
			return true
		}
	}

	// Fallback: Check error string for compatibility with errors
	// that might not be properly typed (e.g., from proxy or older versions)
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "authentication failed")
}
