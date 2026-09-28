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

	"masterdnsvpn-go/internal/sessioncrypto"
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
	// key is the subscriber secret session v2 is keyed from. Derived from the
	// UUID, which other subscribers do not have - unlike the node key.
	key  sessioncrypto.UserKey
	up   atomic.Int64
	down atomic.Int64

	// Speed limit and the addresses this user is currently reachable from.
	// Both are per-account rather than per-session on purpose: a limit is a
	// property of the subscriber, and one subscriber may hold several sessions
	// at once - pacing each session separately would multiply their allowance by
	// however many they opened.
	limitMu sync.Mutex
	bucket  *tokenBucket
	addrs   onlineAddrs
}

// setSpeedLimit replaces the account's pacing. bytesPerSecond <= 0 removes it.
func (a *userAccount) setSpeedLimit(bytesPerSecond int64) {
	if a == nil {
		return
	}
	a.limitMu.Lock()
	a.bucket = newTokenBucket(bytesPerSecond)
	a.limitMu.Unlock()
}

// noteAddr records a sighting of the client's address. Nil-safe on the account
// so the hot packet path can call it without first checking whether the session
// belongs to a user - a standalone session simply has none.
func (a *userAccount) noteAddr(ip string, now time.Time, n int64) {
	if a == nil {
		return
	}
	a.addrs.note(ip, now, n)
}

func (a *userAccount) limiter() *tokenBucket {
	if a == nil {
		return nil
	}
	a.limitMu.Lock()
	b := a.bucket
	a.limitMu.Unlock()
	return b
}

// userRegistry maps handshake tokens to accounts. Safe for concurrent use.
type userRegistry struct {
	secret []byte
	// mask lets the packet path find a sealed (v2) frame's session before it
	// knows which session key to open it with.
	mask   sessioncrypto.MaskKey
	mu     sync.RWMutex
	byTok  map[UserToken]*userAccount
	byUUID map[string]UserToken
}

func newUserRegistry(secret []byte) *userRegistry {
	return &userRegistry{
		secret: append([]byte(nil), secret...),
		mask:   sessioncrypto.DeriveMaskKey(secret),
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
		r.byTok[tok] = &userAccount{
			uuid: uuid,
			key:  sessioncrypto.DeriveUserKey(r.secret, uuid),
		}
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

// byUUIDAccount returns the account for a UUID, or nil when unregistered.
func (r *userRegistry) byUUIDAccount(uuid string) *userAccount {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	tok, ok := r.byUUID[uuid]
	if !ok {
		return nil
	}
	return r.byTok[tok]
}

// onlineIPs collects every user's recently-seen addresses.
func (r *userRegistry) onlineIPs(now time.Time) map[string][]string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	accounts := make([]*userAccount, 0, len(r.byTok))
	for _, a := range r.byTok {
		accounts = append(accounts, a)
	}
	r.mu.RUnlock()

	// Built outside the registry lock: pruning touches each account's own lock,
	// and holding the registry lock across all of them would block every
	// handshake on the node for the duration of a report.
	out := make(map[string][]string, len(accounts))
	for _, a := range accounts {
		if ips := a.addrs.list(now); len(ips) > 0 {
			out[a.uuid] = ips
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// onlineTraffic collects, per user, the bytes each of their live addresses has
// carried since the last reset.
func (r *userRegistry) onlineTraffic(now time.Time, reset bool) map[string]map[string]int64 {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	accounts := make([]*userAccount, 0, len(r.byTok))
	for _, a := range r.byTok {
		accounts = append(accounts, a)
	}
	r.mu.RUnlock()

	// Built outside the registry lock, for the reason onlineIPs gives.
	out := make(map[string]map[string]int64, len(accounts))
	for _, a := range accounts {
		if t := a.addrs.traffic(now, reset); len(t) > 0 {
			out[a.uuid] = t
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

// Both directions are charged to the same bucket, so a subscriber's limit is
// their total throughput rather than that much in each direction. Charged after
// the transfer, like the counters, so the byte count is the real one.
func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.user.down.Add(int64(n))
		c.user.limiter().wait(n)
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.user.up.Add(int64(n))
		c.user.limiter().wait(n)
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

// SessionAuthorizer decides whether an authenticated user may open a session
// from ip. Returning false rejects the handshake.
//
// The policy lives with the embedder, not here: a device limit is a property of
// the subscription, counted across every node the subscriber might be on, and
// only the panel-facing side knows that. This tunnel knows one node.
type SessionAuthorizer func(uuid, ip string) bool

// SetSessionAuthorizer installs the authorisation hook. Passing nil removes it,
// which admits every authenticated user - the behaviour before one was set.
func (s *Server) SetSessionAuthorizer(fn SessionAuthorizer) {
	if s == nil {
		return
	}
	s.authorizerMu.Lock()
	s.authorizer = fn
	s.authorizerMu.Unlock()
}

// authorizeSession applies the hook, admitting when none is installed. A node
// with no authorizer must keep working exactly as it did.
func (s *Server) authorizeSession(uuid, ip string) bool {
	if s == nil {
		return true
	}
	s.authorizerMu.RLock()
	fn := s.authorizer
	s.authorizerMu.RUnlock()
	if fn == nil {
		return true
	}
	return fn(uuid, ip)
}

// SetUserSpeedLimit paces a user to bytesPerSecond across both directions.
// Zero or negative removes the limit. Unknown users are ignored, so the caller
// can push the panel's whole list without checking membership first.
func (s *Server) SetUserSpeedLimit(uuid string, bytesPerSecond int64) {
	if s == nil || s.users == nil || uuid == "" {
		return
	}
	s.users.byUUIDAccount(uuid).setSpeedLimit(bytesPerSecond)
}

// OnlineIPs reports the source addresses each user has been seen from recently,
// keyed by UUID. Only users with at least one live address appear.
//
// This is what lets a panel count devices on an mdns node. Until it existed the
// node reported no addresses at all, so a device limit could not be enforced
// here while every other protocol in the fleet enforced one.
func (s *Server) OnlineIPs() map[string][]string {
	if s == nil || s.users == nil {
		return nil
	}
	return s.users.onlineIPs(time.Now())
}

// OnlineIPTraffic reports, per user and per live address, the bytes carried
// since the last reset - the evidence a caller needs to tell a real device from
// one address out of a carrier's rotating pool.
//
// Without it the only available test is "did this user move any data", which
// passes for every address the user was seen from at once. That is what turned
// one phone behind a NAT pool into a crowd of devices and locked the customer
// out of their own account on the other protocols.
func (s *Server) OnlineIPTraffic(reset bool) map[string]map[string]int64 {
	if s == nil || s.users == nil {
		return nil
	}
	return s.users.onlineTraffic(time.Now(), reset)
}
