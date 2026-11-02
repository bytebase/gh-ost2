/*
   Copyright 2022 GitHub Inc.
	 See https://github.com/github/gh-ost/blob/master/LICENSE
*/

package binlog

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/github/gh-ost/go/base"
	"github.com/github/gh-ost/go/mysql"
	"github.com/github/gh-ost/go/sql"

	"time"

	"context"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
)

// ErrMaxAuthFailures marks the authentication failure that crossed MaxAuthFailures.
// The streamer checks for it to stop reconnecting instead of retrying forever.
var ErrMaxAuthFailures = errors.New("max authentication failures reached")

// MySQL error codes that mean the credentials or the host were rejected.
const (
	errDBAccessDenied     = 1044 // access denied for user to database
	errAccessDenied       = 1045 // access denied for user (using password: YES/NO)
	errHostNotAllowed     = 1130 // host is not allowed to connect
	errAccessDeniedNoPass = 1698 // access denied (no password provided)
	errAccountLocked      = 3118 // account has been locked
)

type RowsEventFilterFunc func(databaseName, tableName string) bool

func newRowsEventDecodeFunc(rowsEventFilter RowsEventFilterFunc) func(*replication.RowsEvent, []byte) error {
	if rowsEventFilter == nil {
		return nil
	}
	return func(rowsEvent *replication.RowsEvent, data []byte) error {
		pos, err := rowsEvent.DecodeHeader(data)
		if err != nil {
			return err
		}
		if !rowsEventFilter(string(rowsEvent.Table.Schema), string(rowsEvent.Table.Table)) {
			return nil
		}
		return rowsEvent.DecodeData(pos, data)
	}
}

type GoMySQLReader struct {
	migrationContext        *base.MigrationContext
	connectionConfig        *mysql.ConnectionConfig
	binlogSyncer            *replication.BinlogSyncer
	binlogStreamer          *replication.BinlogStreamer
	currentCoordinates      mysql.BinlogCoordinates
	currentCoordinatesMutex *sync.Mutex
	// LastTrxCoords are the coordinates of the last transaction completely read.
	// If using the file coordinates it is binlog position of the transaction's XID event.
	LastTrxCoords mysql.BinlogCoordinates
}

func NewGoMySQLReader(migrationContext *base.MigrationContext, rowsEventFilters ...RowsEventFilterFunc) *GoMySQLReader {
	connectionConfig := migrationContext.InspectorConnectionConfig
	var rowsEventFilter RowsEventFilterFunc
	if len(rowsEventFilters) > 0 {
		rowsEventFilter = rowsEventFilters[0]
	}
	config := replication.BinlogSyncerConfig{
		ServerID:                uint32(migrationContext.ReplicaServerId),
		Flavor:                  mysql.FlavorFor(migrationContext.InspectorMySQLVersion),
		Host:                    connectionConfig.Key.Hostname,
		Port:                    uint16(connectionConfig.Key.Port),
		User:                    connectionConfig.User,
		Password:                connectionConfig.Password,
		TLSConfig:               connectionConfig.TLSConfig(),
		UseDecimal:              true,
		TimestampStringLocation: time.UTC,
		MaxReconnectAttempts:    migrationContext.BinlogSyncerMaxReconnectAttempts,
	}
	config.RowsEventDecodeFunc = newRowsEventDecodeFunc(rowsEventFilter)
	return &GoMySQLReader{
		migrationContext:        migrationContext,
		connectionConfig:        connectionConfig,
		currentCoordinatesMutex: &sync.Mutex{},
		binlogSyncer:            replication.NewBinlogSyncer(config),
	}
}

// isAuthenticationError reports whether err means the server rejected the
// credentials or the host, rather than failing for some transient reason.
func (gmr *GoMySQLReader) isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	var myErr *gomysql.MyError
	if errors.As(err, &myErr) {
		switch myErr.Code {
		case errAccessDenied, errDBAccessDenied, errHostNotAllowed, errAccessDeniedNoPass, errAccountLocked:
			return true
		}
	}

	// Errors relayed through a proxy arrive untyped, so fall back to the message.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "authentication failed")
}

// resetAuthFailureCount clears the consecutive-failure count after the connection
// or the event read succeeded.
func (gmr *GoMySQLReader) resetAuthFailureCount(context string) {
	if gmr.migrationContext.AuthFailureCount > 0 {
		gmr.migrationContext.Log.Infof("%s successful, resetting auth failure count from %d to 0", context, gmr.migrationContext.AuthFailureCount)
		gmr.migrationContext.AuthFailureCount = 0
	}
}

// handleAuthError passes err through, counting consecutive authentication failures and
// wrapping the one that crosses MaxAuthFailures in ErrMaxAuthFailures. A nil err resets
// the count.
func (gmr *GoMySQLReader) handleAuthError(err error, context string) error {
	if err == nil {
		gmr.resetAuthFailureCount(context)
		return nil
	}

	if !gmr.isAuthenticationError(err) {
		return err
	}

	gmr.migrationContext.AuthFailureCount++

	if gmr.migrationContext.MaxAuthFailures > 0 && gmr.migrationContext.AuthFailureCount >= gmr.migrationContext.MaxAuthFailures {
		return fmt.Errorf("%w: authentication failed %d times (max: %d) during %s, aborting to prevent firewall blocking: %w",
			ErrMaxAuthFailures, gmr.migrationContext.AuthFailureCount, gmr.migrationContext.MaxAuthFailures, context, err)
	}

	gmr.migrationContext.Log.Errorf("Authentication failure #%d during %s (max: %d): %v",
		gmr.migrationContext.AuthFailureCount, context, gmr.migrationContext.MaxAuthFailures, err)

	return err
}

// ConnectBinlogStreamer
func (gmr *GoMySQLReader) ConnectBinlogStreamer(coordinates mysql.BinlogCoordinates) (err error) {
	if coordinates.IsEmpty() {
		return gmr.migrationContext.Log.Errorf("empty coordinates at ConnectBinlogStreamer()")
	}

	gmr.currentCoordinatesMutex.Lock()
	defer gmr.currentCoordinatesMutex.Unlock()
	gmr.currentCoordinates = coordinates.Clone()
	gmr.migrationContext.Log.Infof("Connecting binlog streamer at %+v", coordinates)

	// Start sync with specified GTID set or binlog file and position
	if gmr.migrationContext.UseGTIDs {
		coords := coordinates.(*mysql.GTIDBinlogCoordinates)
		gmr.binlogStreamer, err = gmr.binlogSyncer.StartSyncGTID(coords.GTIDSet.Clone())
	} else {
		coords := gmr.currentCoordinates.(*mysql.FileBinlogCoordinates)
		gmr.binlogStreamer, err = gmr.binlogSyncer.StartSync(gomysql.Position{
			Name: coords.LogFile,
			Pos:  uint32(coords.LogPos)},
		)
	}
	return gmr.handleAuthError(err, "connection")
}

func (gmr *GoMySQLReader) GetCurrentBinlogCoordinates() mysql.BinlogCoordinates {
	gmr.currentCoordinatesMutex.Lock()
	defer gmr.currentCoordinatesMutex.Unlock()
	return gmr.currentCoordinates.Clone()
}

func (gmr *GoMySQLReader) handleRowsEvent(ev *replication.BinlogEvent, rowsEvent *replication.RowsEvent, entriesChannel chan<- *BinlogEntry) error {
	currentCoords := gmr.GetCurrentBinlogCoordinates()
	dml := ToEventDML(ev.Header.EventType.String())
	if dml == NotDML {
		return fmt.Errorf("unknown DML type: %s", ev.Header.EventType.String())
	}
	for i, row := range rowsEvent.Rows {
		if dml == UpdateDML && i%2 == 1 {
			// An update has two rows (WHERE+SET)
			// We do both at the same time
			continue
		}
		binlogEntry := NewBinlogEntryAt(currentCoords)
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
	return nil
}

// StreamEvents
func (gmr *GoMySQLReader) StreamEvents(canStopStreaming func() bool, entriesChannel chan<- *BinlogEntry) error {
	for !canStopStreaming() {
		ev, err := gmr.binlogStreamer.GetEvent(context.Background())
		if err != nil {
			return gmr.handleAuthError(err, "streaming")
		}
		gmr.resetAuthFailureCount("event retrieval")

		// Update binlog coords if using file-based coords.
		// GTID coordinates are updated on receiving GTID events.
		if !gmr.migrationContext.UseGTIDs {
			gmr.currentCoordinatesMutex.Lock()
			coords := gmr.currentCoordinates.(*mysql.FileBinlogCoordinates)
			prevCoords := coords.Clone().(*mysql.FileBinlogCoordinates)
			coords.LogPos = int64(ev.Header.LogPos)
			coords.EventSize = int64(ev.Header.EventSize)
			if coords.IsLogPosOverflowBeyond4Bytes(prevCoords) {
				gmr.currentCoordinatesMutex.Unlock()
				return fmt.Errorf("unexpected rows event at %+v, the binlog end_log_pos is overflow 4 bytes", coords)
			}
			gmr.currentCoordinatesMutex.Unlock()
		}

		switch event := ev.Event.(type) {
		case *replication.GTIDEvent, *replication.MariadbGTIDEvent:
			// MySQL emits *GTIDEvent, MariaDB emits *MariadbGTIDEvent; both
			// implement BinlogGTIDEvent.GTIDNext() returning the GTID about to
			// be applied. We advance currentCoordinates by merging it into the
			// running GTID set, regardless of flavor.
			if !gmr.migrationContext.UseGTIDs {
				continue
			}
			gtidEvent, ok := ev.Event.(gomysql.BinlogGTIDEvent)
			if !ok {
				return fmt.Errorf("unexpected GTID event type: %T", ev.Event)
			}
			nextGTID, err := gtidEvent.GTIDNext()
			if err != nil {
				return err
			}
			gmr.currentCoordinatesMutex.Lock()
			if gmr.LastTrxCoords != nil {
				gmr.currentCoordinates = gmr.LastTrxCoords.Clone()
			}
			coords := gmr.currentCoordinates.(*mysql.GTIDBinlogCoordinates)
			if coords.GTIDSet == nil {
				coords.GTIDSet = nextGTID
			} else if err := coords.GTIDSet.Update(nextGTID.String()); err != nil {
				gmr.currentCoordinatesMutex.Unlock()
				return err
			}
			gmr.currentCoordinatesMutex.Unlock()
		case *replication.RotateEvent:
			if gmr.migrationContext.UseGTIDs {
				continue
			}
			gmr.currentCoordinatesMutex.Lock()
			coords := gmr.currentCoordinates.(*mysql.FileBinlogCoordinates)
			coords.LogFile = string(event.NextLogName)
			gmr.migrationContext.Log.Infof("rotate to next log from %s:%d to %s", coords.LogFile, int64(ev.Header.LogPos), event.NextLogName)
			gmr.currentCoordinatesMutex.Unlock()
		case *replication.XIDEvent:
			if gmr.migrationContext.UseGTIDs {
				// event.GSet is the full executed GTID set maintained by the
				// syncer (MysqlGTIDSet or MariadbGTIDSet depending on flavor).
				if event.GSet != nil {
					gmr.LastTrxCoords = &mysql.GTIDBinlogCoordinates{GTIDSet: event.GSet}
				}
			} else {
				gmr.LastTrxCoords = gmr.currentCoordinates.Clone()
			}
		case *replication.RowsEvent:
			if err := gmr.handleRowsEvent(ev, event, entriesChannel); err != nil {
				return err
			}
		}
	}
	gmr.migrationContext.Log.Debugf("done streaming events")

	return nil
}

func (gmr *GoMySQLReader) Close() error {
	gmr.binlogSyncer.Close()
	return nil
}
