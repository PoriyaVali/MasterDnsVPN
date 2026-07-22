// ==============================================================================
// MasterDnsVPN — multi-user registry (V2bX / V2board integration)
//
// A node runs one shared transport key (the codec) for obfuscation; individual
// users are authenticated and metered by an 8-byte token derived from their
// V2board UUID: token = HMAC-SHA256(node_secret, uuid)[:8]. The raw UUID never
// travels on the wire and a leaked token cannot be reversed to the account.
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/usertoken"
)

// UserTokenLen is the number of HMAC bytes carried in the handshake to identify
// a user. 8 bytes = 64 bits: negligible collision risk across a node's users,
// tiny wire overhead.
const UserTokenLen = usertoken.Len

// UserToken is the fixed-size identity a client presents at SESSION_INIT.
type UserToken = usertoken.Token

// UserBytes is a per-user traffic sample returned by Traffic().
type UserBytes struct {
	UUID     string
	Upload   int64
	Download int64
}

type userAccount struct {
	uuid string
	up   atomic.Int64
	down atomic.Int64
}

// userRegistry maps handshake tokens to accounts. Safe for concurrent use.
type userRegistry struct {
	secret []byte
	mu     sync.RWMutex
	byTok  map[UserToken]*userAccount
	byUUID map[string]UserToken
}

func newUserRegistry(secret []byte) *userRegistry {
	return &userRegistry{
		secret: append([]byte(nil), secret...),
		byTok:  make(map[UserToken]*userAccount),
		byUUID: make(map[string]UserToken),
	}
}

// DeriveUserToken computes the handshake token for a UUID under a node secret.
// Exported so clients (and tests) derive the exact same value.
func DeriveUserToken(secret []byte, uuid string) UserToken {
	return usertoken.Derive(secret, uuid)
}

func (r *userRegistry) add(uuid string) UserToken {
	tok := DeriveUserToken(r.secret, uuid)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byTok[tok]; !ok {
		r.byTok[tok] = &userAccount{uuid: uuid}
		r.byUUID[uuid] = tok
	}
	return tok
}

// del removes a user and returns the account that was removed, or nil if the
// user was not registered. The caller needs the account to find the sessions it
// still owns: revoking a user has to reach the traffic already flowing, not
// only the next handshake.
func (r *userRegistry) del(uuid string) *userAccount {
	r.mu.Lock()
	defer r.mu.Unlock()
	tok, ok := r.byUUID[uuid]
	if !ok {
		return nil
	}
	account := r.byTok[tok]
	delete(r.byTok, tok)
	delete(r.byUUID, uuid)
	return account
}

// lookup returns the account for a presented token, or nil if unknown (= reject).
func (r *userRegistry) lookup(tok UserToken) *userAccount {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byTok[tok]
}

func (r *userRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byTok)
}

// sample reads every user's counters, optionally resetting them (for the
// panel report cycle). Only users with non-zero traffic are returned.
func (r *userRegistry) sample(reset bool) []UserBytes {
	r.mu.RLock()
	accounts := make([]*userAccount, 0, len(r.byTok))
	for _, a := range r.byTok {
		accounts = append(accounts, a)
	}
	r.mu.RUnlock()

	out := make([]UserBytes, 0, len(accounts))
	for _, a := range accounts {
		var up, down int64
		if reset {
			up = a.up.Swap(0)
			down = a.down.Swap(0)
		} else {
			up = a.up.Load()
			down = a.down.Load()
		}
		if up != 0 || down != 0 {
			out = append(out, UserBytes{UUID: a.uuid, Upload: up, Download: down})
		}
	}
	return out
}

// countingConn wraps the per-stream upstream connection and meters the tunnel
// payload for its owning user. Read pulls destination bytes heading DOWN to the
// client; Write pushes client bytes UP to the destination. DNS/transport
// overhead is deliberately excluded so metering matches the other cores.
type countingConn struct {
	net.Conn
	user *userAccount
}

// wrapUserCounting returns conn unchanged for standalone streams (user == nil),
// otherwise a metering wrapper tied to the account. The wrapper is still a
// net.Conn (LocalAddr/Deadlines delegate to the inner connection).
func wrapUserCounting(conn net.Conn, user *userAccount) net.Conn {
	if user == nil || conn == nil {
		return conn
	}
	return &countingConn{Conn: conn, user: user}
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.user.down.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.user.up.Add(int64(n))
	}
	return n, err
}

// ---- Server public API (embeddable library surface) ----

// AddUser registers a V2board user by UUID. Idempotent.
func (s *Server) AddUser(uuid string) {
	if s.users == nil || uuid == "" {
		return
	}
	s.users.add(uuid)
}

// DelUser removes a user: their next handshake is rejected AND the sessions
// they still have open are torn down.
//
// Closing the live sessions is the part that makes revocation mean anything.
// Without it the panel can revoke a user - expired, out of data, out of credit -
// and they keep the service they are no longer paying for, indefinitely, because
// an active session refreshes its own idle timer.
func (s *Server) DelUser(uuid string) {
	if s == nil || s.users == nil {
		return
	}
	account := s.users.del(uuid)
	if account == nil || s.sessions == nil {
		return
	}

	// CloseUserSessions returns with the store lock released, so the per-session
	// cleanup below runs outside it - the same order sessionCleanupLoop uses.
	// Doing this work while holding the lock would stall every session on the
	// node, and cleanup reaches for locks of its own.
	closed := s.sessions.CloseUserSessions(account, time.Now(), s.cfg.ClosedSessionRetention())
	for _, session := range closed {
		s.cleanupClosedSession(session.ID, session.record)
	}
	if len(closed) > 0 && s.log != nil {
		s.log.Infof(
			"\U0001F512 <yellow>Revoked user, closed <cyan>%d</cyan> live session(s)</yellow>",
			len(closed),
		)
	}
}

// UserCount reports how many users are currently registered.
func (s *Server) UserCount() int {
	if s.users == nil {
		return 0
	}
	return s.users.count()
}

// Traffic returns per-user byte counters, resetting them when reset is true.
func (s *Server) Traffic(reset bool) []UserBytes {
	if s.users == nil {
		return nil
	}
	return s.users.sample(reset)
}
