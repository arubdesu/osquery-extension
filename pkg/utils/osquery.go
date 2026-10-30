package utils

import (
	"fmt"
	"time"

	"github.com/osquery/osquery-go"
)

type OsqueryClienter interface {
	NewOsqueryClient() (OsqueryClient, error)
}

// OsqueryClient is deliberately narrow, and currently narrower than it should be.
//
// KNOWN GAP: osquery-go also provides QueryRowsContext,
// QueryRowContext and QueryContext, and *ExtensionManagerClient satisfies them today. They
// are absent here, so every caller queries with an implicit context.Background() and cannot
// honour a cancelled table query or bound the call by its own deadline. Adding them is
// additive -- the concrete client needs nothing and existing callers are unaffected -- but
// it widens an interface four tables depend on, so it wants its own review.
type OsqueryClient interface {
	QueryRows(query string) ([]map[string]string, error)
	QueryRow(query string) (map[string]string, error)
	Close()
}

// SocketClienter opens clients on osquery's extension socket at socketPath, with the timeout
// every table uses.
func SocketClienter(socketPath string) OsqueryClienter {
	return &SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second}
}

type SocketOsqueryClienter struct {
	SocketPath string
	Timeout    time.Duration
}

func (s *SocketOsqueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	osqueryClient, err := osquery.NewClient(s.SocketPath, s.Timeout)
	if err != nil {
		return nil, fmt.Errorf("could not create osquery client: %w", err)
	}
	return osqueryClient, nil
}

type MockOsqueryClienter struct {
	Data map[string][]map[string]string
	// Err, when set, is returned in place of a client, as when the socket cannot be reached.
	Err error
}

func (m *MockOsqueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return &MockOsqueryClient{Data: m.Data}, nil
}

type MockOsqueryClient struct {
	Data map[string][]map[string]string
}

func (m *MockOsqueryClient) QueryRows(query string) ([]map[string]string, error) {
	return m.Data[query], nil
}

func (m *MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return m.Data[query][0], nil
}

func (m *MockOsqueryClient) Close() {}
