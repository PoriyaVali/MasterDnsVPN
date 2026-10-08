// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mlq"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrSessionTableFull = errors.New("session table full")

// ErrUserSessionLimit is a subscriber already holding MaxSessionsPerUser busy
// sessions. The client is answered the same way as for a full table.
var ErrUserSessionLimit = errors.New("per-user session limit reached")

// errSessionSignatureTaken: a SESSION_INIT repeated a live session's signature
// but authenticated as a different user.
var errSessionSignatureTaken = errors.New("session signature belongs to another user")

const (
	maxServerSessionID    = 255
	maxServerSessionSlots = 255
	sessionInitDataSize   = 10
	minSessionMTU         = 10
	maxSessionMTU         = 4096
)

type sessionRecord struct {
	mu sync.RWMutex

	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	UploadCompression   uint8
	DownloadCompression uint8
	UploadMTU           uint16
	DownloadMTU         uint16
	DownloadMTUBytes    int
	VerifyCode          [4]byte
	Signature           [sessionInitDataSize]byte
	user                *userAccount // multi-user: owning V2board account (nil = standalone)
	// Session protocol v2 (see package sessioncrypto): every packet of this
	// session is sealed under its own keys, and a packet that is not is refused.
	v2   bool
	keys *sessioncrypto.Keys
	// deviceAddr stands in for the client address when counting devices; ""
	// means the client sent no device, and the resolver address is used.
	deviceAddr                          string
	MaxPackedBlocks                     int
	StreamReadBufferSize                int
	CreatedAt                           time.Time
	ReuseUntil                          time.Time
	reuseUntilUnixNano                  int64
	lastActivityUnixNano                int64
	lastDeferredCleanupActivityUnixNano int64

	// New fields for ARQ refactor
	Streams                         map[uint16]*Stream_server
	ActiveStreams                   []uint16 // Sorted list of active stream IDs for Round-Robin
	activeStreamSetVersion          uint64
	activeStreamSnapshotIDs         []int32
	activeStreamSnapshotStreams     []*Stream_server
	activeStreamSnapshotVersion     uint64
	RRStreamID                      int32  // Last served stream ID for RR
	EnqueueSeq                      uint64 // Global sequence for FIFO inside same priority
	StreamQueueCap                  int
	StreamsMu                       sync.RWMutex
	RecentlyClosed                  map[uint16]recentlyClosedStreamRecord
	RecentlyClosedHeap              recentlyClosedHeap
	RecentlyClosedTTL               time.Duration
	RecentlyClosedCap               int
	OrphanQueue                     *mlq.MultiLevelQueue[VpnProto.Packet]
	LastPackedControlBlock          *VpnProto.Packet
	LastPackedControlBlockRemaining int
	MaxActiveStreamsPerSession      int
	closedFlag                      uint32
	streamCleanup                   func(uint8, uint16)

	// early holds data for streams whose SYN has not arrived (early_data.go).
	early earlyDataBuffer
}

type recentlyClosedStreamRecord struct {
	ClosedAt       time.Time
	SuppressOrphan bool
}

type recentlyClosedEntry struct {
	streamID uint16
	closedAt time.Time
}

type recentlyClosedHeap []recentlyClosedEntry

func (h recentlyClosedHeap) Len() int { return len(h) }

func (h recentlyClosedHeap) Less(i, j int) bool {
	return h[i].closedAt.Before(h[j].closedAt)
}

func (h recentlyClosedHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *recentlyClosedHeap) Push(x any) {
	*h = append(*h, x.(recentlyClosedEntry))
}

func (h *recentlyClosedHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// serverStreamTXPacket represents a queued packet pending transmission or retransmission.
type serverStreamTXPacket struct {
	PacketType      uint8
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
	CreatedAt       time.Time
	TTL             time.Duration
}

var txPacketPool = sync.Pool{
	New: func() any {
		return &serverStreamTXPacket{}
	},
}

func getTXPacketFromPool() *serverStreamTXPacket {
	return txPacketPool.Get().(*serverStreamTXPacket)
}

func putTXPacketToPool(p *serverStreamTXPacket) {
	if p == nil {
		return
	}
	p.Payload = nil
	p.TTL = 0
	txPacketPool.Put(p)
}

// getEffectivePriority maps packet types to priorities (0 is highest, 5 is lowest).
func getEffectivePriority(packetType uint8, basePriority int) int {
	return Enums.NormalizePacketPriority(packetType, basePriority)
}

type sessionRuntimeView struct {
	// user is the account this session belongs to (nil for a standalone
	// session). Carried on the view so the packet path can meter the client's
	// address without reaching back into the record and taking its lock.
	user                *userAccount
	v2                  bool
	keys                *sessioncrypto.Keys
	deviceAddr          string
	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	ResponseBase64      bool
	DownloadCompression uint8
	DownloadMTU         uint16
	DownloadMTUBytes    int
	MaxPackedBlocks     int
}

type closedSessionRecord struct {
	Cookie       uint8
	ResponseMode uint8
	ExpiresAt    time.Time
}

type sessionLookupState uint8

const (
	sessionLookupUnknown sessionLookupState = iota
	sessionLookupActive
	sessionLookupClosed
)

type sessionLookupResult struct {
	Cookie       uint8
	ResponseMode uint8
	State        sessionLookupState
}

type sessionValidationResult struct {
	Lookup sessionLookupResult
	Known  bool
	Valid  bool
	// Unsealed: the session is v2 and this packet was not sealed for it.
	Unsealed bool
	Active   *sessionRuntimeView
}

type closedSessionCleanup struct {
	ID     uint8
	record *sessionRecord
}

type idleDeferredCleanup struct {
	ID               uint8
	lastActivityNano int64
}

type sessionStore struct {
	mu                     sync.RWMutex
	nextID                 uint16
	activeCount            uint16
	nextReuseSweepUnixNano int64
	cookieBytes            [32]byte
	cookieIndex            int
	byID                   [maxServerSessionID + 1]*sessionRecord
	bySig                  map[[sessionInitDataSize]byte]uint8
	recentClosed           map[uint8]closedSessionRecord
	orphanQueueCap         int
	streamQueueCap         int
	maxActiveSessions      int
	maxActiveStreams       int
	sessionInitTTL         time.Duration
	recentlyClosedTTL      time.Duration
	recentlyClosedCap      int
	// maxSessionsPerUser caps one subscriber's live sessions (0 = no cap).
	maxSessionsPerUser int
	// closedRetention is how long an evicted session keeps answering "closed".
	closedRetention time.Duration
	// streamCleanup is handed to every record this store creates.
	streamCleanup func(uint8, uint16)
}

func newSessionStore(orphanQueueCap int, streamQueueCap int, options ...any) *sessionStore {
	if orphanQueueCap < 1 {
		orphanQueueCap = 8
	}
	if streamQueueCap < 1 {
		streamQueueCap = 32
	}

	sessionInitTTL := 10 * time.Minute
	recentlyClosedTTL := 600 * time.Second
	recentlyClosedCap := 2000
	if len(options) > 0 {
		if v, ok := options[0].(time.Duration); ok && v > 0 {
			sessionInitTTL = v
		}
	}
	if len(options) > 1 {
		if v, ok := options[1].(time.Duration); ok && v > 0 {
			recentlyClosedTTL = v
		}
	}
	if len(options) > 2 {
		if v, ok := options[2].(int); ok && v > 0 {
			recentlyClosedCap = v
		}
	}
	return &sessionStore{
		bySig:             make(map[[sessionInitDataSize]byte]uint8, 64),
		recentClosed:      make(map[uint8]closedSessionRecord, 32),
		cookieIndex:       32,
		nextID:            1,
		orphanQueueCap:    orphanQueueCap,
		streamQueueCap:    streamQueueCap,
		maxActiveSessions: maxServerSessionSlots,
		maxActiveStreams:  1000,
		sessionInitTTL:    sessionInitTTL,
		recentlyClosedTTL: recentlyClosedTTL,
		recentlyClosedCap: recentlyClosedCap,
		closedRetention:   600 * time.Second,
	}
}

func (s *sessionStore) findOrCreate(
	payload []byte,
	uploadCompressionType uint8,
	downloadCompressionType uint8,
	maxPacketsPerBatch int,
	maxClientUploadMTU int,
	maxClientDownloadMTU int,
) (*sessionRecord, bool, error) {
	record, reused, _, err := s.findOrCreateFor(sessionOwner{}, payload, uploadCompressionType, downloadCompressionType, maxPacketsPerBatch, maxClientUploadMTU, maxClientDownloadMTU)
	return record, reused, err
}

// sessionOwner is everything an authenticated SESSION_INIT established about
// who is asking. The zero value is a standalone (single-key, v1) session.
type sessionOwner struct {
	user       *userAccount
	v2         bool
	keys       *sessioncrypto.Keys
	deviceAddr string
}

const (
	// A live client is heard from at least every ~15s (its coldest ping), so a
	// session quiet this long has lost its client. Only ever evicted when room
	// is needed.
	perUserEvictIdle = 30 * time.Second
	tableEvictIdle   = 60 * time.Second
)

// findOrCreateFor finds the session a SESSION_INIT names, or creates it.
// Sessions it had to evict to make room are returned for the caller to clean
// up outside the lock, whether or not the init itself succeeded.
//
// 🔴 A repeated SESSION_INIT is matched to its session by the 10-byte
// signature alone, and the answer is that session's ID and cookie - everything
// a client needs to send and receive on it. So the match must also be the same
// user, speaking the same protocol version from the same device: otherwise
// anyone who presents another subscriber's signature under their own valid
// token is handed that subscriber's session, and a v1 init could pull a v2
// session's handle back out in clear. The owner is attached here, under the
// store lock, instead of after the record has been published to every packet
// worker.
//
// Room. Session IDs are 8 bits, so a node holds at most 255 sessions, and a
// client that vanishes without SESSION_CLOSE (a phone changing network) leaves
// its session to idle out over SESSION_TIMEOUT. Two rules keep that from
// locking everyone out: one subscriber holds at most maxSessionsPerUser
// sessions - a new one replaces their longest-quiet one - and a full table
// makes room by evicting the node's longest-quiet session, once it has been
// silent long enough that its client is surely gone.
func (s *sessionStore) findOrCreateFor(
	owner sessionOwner,
	payload []byte,
	uploadCompressionType uint8,
	downloadCompressionType uint8,
	maxPacketsPerBatch int,
	maxClientUploadMTU int,
	maxClientDownloadMTU int,
) (*sessionRecord, bool, []closedSessionCleanup, error) {
	if len(payload) != sessionInitDataSize || !isValidSessionResponseMode(payload[0]) {
		return nil, false, nil, nil
	}

	var signature [sessionInitDataSize]byte
	copy(signature[:], payload[:sessionInitDataSize])

	now := time.Now()
	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireReuseLocked(nowUnixNano)

	if sessionID, ok := s.bySig[signature]; ok {
		if existing := s.byID[sessionID]; existing != nil {
			if nowUnixNano <= existing.reuseUntilUnixNano {
				if existing.user != owner.user || existing.v2 != owner.v2 || existing.deviceAddr != owner.deviceAddr {
					return nil, false, nil, errSessionSignatureTaken
				}
				existing.setLastActivityUnixNano(nowUnixNano)
				return existing, true, nil, nil
			}
		}
		delete(s.bySig, signature)
	}

	var evicted []closedSessionCleanup
	if owner.user != nil && s.maxSessionsPerUser > 0 {
		count, quietest := s.userSessionsLocked(owner.user)
		if count >= s.maxSessionsPerUser {
			if quietest == nil || nowUnixNano-quietest.lastActivity() < perUserEvictIdle.Nanoseconds() {
				return nil, false, nil, ErrUserSessionLimit
			}
			evicted = append(evicted, s.evictLocked(quietest.ID, now))
		}
	}

	slot := s.allocateSlotLocked()
	if slot < 0 {
		if victim := s.quietestLocked(nowUnixNano, tableEvictIdle); victim != nil {
			evicted = append(evicted, s.evictLocked(victim.ID, now))
			slot = s.allocateSlotLocked()
		}
		if slot < 0 {
			return nil, false, evicted, ErrSessionTableFull
		}
	}

	record := &sessionRecord{
		ID:                         uint8(slot),
		user:                       owner.user,
		v2:                         owner.v2,
		keys:                       owner.keys,
		deviceAddr:                 owner.deviceAddr,
		ResponseMode:               payload[0],
		CreatedAt:                  now,
		ReuseUntil:                 now.Add(s.sessionInitTTL),
		Signature:                  signature,
		Streams:                    make(map[uint16]*Stream_server),
		ActiveStreams:              make([]uint16, 0, 8),
		StreamQueueCap:             s.streamQueueCap,
		MaxActiveStreamsPerSession: s.maxActiveStreams,
		RecentlyClosed:             make(map[uint16]recentlyClosedStreamRecord, 8),
		RecentlyClosedHeap:         make(recentlyClosedHeap, 0, 8),
		RecentlyClosedTTL:          s.recentlyClosedTTL,
		RecentlyClosedCap:          s.recentlyClosedCap,
		OrphanQueue:                mlq.New[VpnProto.Packet](s.orphanQueueCap),
		streamCleanup:              s.streamCleanup,
	}

	// Initialize virtual Stream 0 for control packets
	record.ensureStream0(nil) // Caller should update logger if needed
	record.reuseUntilUnixNano = record.ReuseUntil.UnixNano()
	record.setLastActivityUnixNano(nowUnixNano)
	record.UploadCompression = uploadCompressionType
	record.DownloadCompression = downloadCompressionType
	record.applyMTUFromSessionInit(
		binary.BigEndian.Uint16(payload[2:4]),
		binary.BigEndian.Uint16(payload[4:6]),
		maxPacketsPerBatch,
		maxClientUploadMTU,
		maxClientDownloadMTU,
	)
	copy(record.VerifyCode[:], payload[6:10])
	record.Cookie = s.randomCookieLocked()

	s.byID[slot] = record
	s.activeCount++
	s.bySig[signature] = uint8(slot)
	s.updateNextReuseSweepLocked(record.reuseUntilUnixNano)
	delete(s.recentClosed, uint8(slot))
	s.nextID = uint16(nextSessionID(uint8(slot)))
	return record, false, evicted, nil
}

// userSessionsLocked counts a subscriber's sessions and finds their quietest.
func (s *sessionStore) userSessionsLocked(user *userAccount) (int, *sessionRecord) {
	count := 0
	var quietest *sessionRecord
	for id := 1; id <= maxServerSessionID; id++ {
		record := s.byID[id]
		if record == nil || record.user != user {
			continue
		}
		count++
		if quietest == nil || record.lastActivity() < quietest.lastActivity() {
			quietest = record
		}
	}
	return count, quietest
}

// quietestLocked is the session silent the longest, if silent at least minIdle.
func (s *sessionStore) quietestLocked(nowUnixNano int64, minIdle time.Duration) *sessionRecord {
	var quietest *sessionRecord
	for id := 1; id <= maxServerSessionID; id++ {
		record := s.byID[id]
		if record == nil {
			continue
		}
		if quietest == nil || record.lastActivity() < quietest.lastActivity() {
			quietest = record
		}
	}
	if quietest == nil || nowUnixNano-quietest.lastActivity() < minIdle.Nanoseconds() {
		return nil
	}
	return quietest
}

// evictLocked removes a session exactly as an idle expiry does, so its client
// is told "closed" and starts over.
func (s *sessionStore) evictLocked(sessionID uint8, now time.Time) closedSessionCleanup {
	record := s.byID[sessionID]
	delete(s.bySig, record.Signature)
	s.byID[sessionID] = nil
	if s.activeCount > 0 {
		s.activeCount--
	}
	if s.closedRetention > 0 {
		s.recentClosed[sessionID] = closedSessionRecord{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			ExpiresAt:    now.Add(s.closedRetention),
		}
	}
	record.markClosed()
	return closedSessionCleanup{ID: sessionID, record: record}
}

func (s *sessionStore) expireReuseLocked(nowUnixNano int64) {
	if len(s.bySig) == 0 {
		s.nextReuseSweepUnixNano = 0
		return
	}
	if s.nextReuseSweepUnixNano != 0 && nowUnixNano < s.nextReuseSweepUnixNano {
		return
	}

	nextReuseSweepUnixNano := int64(0)
	for signature, sessionID := range s.bySig {
		record := s.byID[sessionID]
		if record == nil || nowUnixNano > record.reuseUntilUnixNano {
			delete(s.bySig, signature)
			continue
		}
		if nextReuseSweepUnixNano == 0 || record.reuseUntilUnixNano < nextReuseSweepUnixNano {
			nextReuseSweepUnixNano = record.reuseUntilUnixNano
		}
	}
	s.nextReuseSweepUnixNano = nextReuseSweepUnixNano
}

func (s *sessionStore) Get(sessionID uint8) (*sessionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record := s.byID[sessionID]
	if record == nil || record.isClosed() {
		return nil, false
	}
	return record, true
}

func (s *sessionStore) HasActive(sessionID uint8) bool {
	if s == nil || sessionID == 0 {
		return false
	}

	s.mu.RLock()
	record := s.byID[sessionID]
	s.mu.RUnlock()
	return record != nil && !record.isClosed()
}

func (s *sessionStore) Lookup(sessionID uint8) (sessionLookupResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record := s.byID[sessionID]; record != nil {
		return sessionLookupResult{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			State:        sessionLookupActive,
		}, true
	}

	if record, ok := s.recentClosed[sessionID]; ok {
		return sessionLookupResult{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			State:        sessionLookupClosed,
		}, true
	}

	return sessionLookupResult{}, false
}

func (s *sessionStore) ValidateAndTouch(sessionID uint8, cookie uint8, now time.Time) sessionValidationResult {
	return s.ValidateAndTouchAuth(sessionID, cookie, false, now)
}

// ValidateAndTouchAuth is ValidateAndTouch knowing whether the packet arrived
// sealed under the session's own keys. A v2 session accepts nothing else: an
// unsealed packet naming it is someone guessing its ID and cookie, and is
// refused without refreshing the session's idle clock. A sealed packet is
// equally refused by a v1 session, which has no keys it could have been
// sealed with.
func (s *sessionStore) ValidateAndTouchAuth(sessionID uint8, cookie uint8, sealed bool, now time.Time) sessionValidationResult {
	s.mu.RLock()
	if record := s.byID[sessionID]; record != nil {
		result := sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				State:        sessionLookupActive,
			},
			Known:    true,
			Valid:    record.Cookie == cookie && sealed == record.v2,
			Unsealed: record.v2 && !sealed,
		}
		if result.Valid {
			view := record.runtimeView()
			result.Active = &view
		}
		s.mu.RUnlock()
		if result.Valid {
			record.setLastActivity(now)
		}
		return result
	}

	if record, ok := s.recentClosed[sessionID]; ok {
		s.mu.RUnlock()
		return sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				State:        sessionLookupClosed,
			},
			Known: true,
			Valid: false,
		}
	}

	s.mu.RUnlock()
	return sessionValidationResult{}
}

func (s *sessionStore) Close(sessionID uint8, now time.Time, retention time.Duration) (*sessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	record.markClosed()

	delete(s.bySig, record.Signature)
	s.byID[sessionID] = nil
	if s.activeCount > 0 {
		s.activeCount--
	}
	if retention > 0 {
		s.recentClosed[sessionID] = closedSessionRecord{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			ExpiresAt:    now.Add(retention),
		}
	} else {
		delete(s.recentClosed, sessionID)
	}
	return record, true
}

func (s *sessionStore) Cleanup(now time.Time, idleTimeout time.Duration, closedRetention time.Duration) []closedSessionCleanup {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUnixNano := now.UnixNano()
	s.expireReuseLocked(nowUnixNano)

	for sessionID, record := range s.recentClosed {
		if !now.Before(record.ExpiresAt) {
			delete(s.recentClosed, sessionID)
		}
	}

	if idleTimeout <= 0 {
		return nil
	}

	expired := make([]closedSessionCleanup, 0, 8)
	idleTimeoutNanos := idleTimeout.Nanoseconds()
	for sessionID := 1; sessionID <= maxServerSessionID; sessionID++ {
		record := s.byID[sessionID]
		if record == nil {
			continue
		}

		lastActivityUnixNano := record.lastActivity()
		if lastActivityUnixNano != 0 && nowUnixNano-lastActivityUnixNano < idleTimeoutNanos {
			continue
		}

		delete(s.bySig, record.Signature)
		s.byID[sessionID] = nil
		if s.activeCount > 0 {
			s.activeCount--
		}
		if closedRetention > 0 {
			s.recentClosed[uint8(sessionID)] = closedSessionRecord{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				ExpiresAt:    now.Add(closedRetention),
			}
		}
		record.markClosed()
		expired = append(expired, closedSessionCleanup{
			ID:     uint8(sessionID),
			record: record,
		})
	}

	return expired
}

// CloseUserSessions tears down every session owned by one account and returns
// them for the same post-processing an idle expiry gets.
//
// A session proves who it belongs to once, at SESSION_INIT, and carries that
// account for the rest of its life; nothing on the data path looks the user up
// again. So removing a user from the registry only turns away the NEXT
// handshake - traffic already flowing keeps flowing, and because the idle timer
// is reset by activity, a session in active use never times out on its own. A
// customer whose credit ran out therefore kept full service for as long as they
// kept using it.
//
// The removal below is deliberately identical to Cleanup's, including the
// recentClosed entry: a client whose session vanishes will retry on the same
// signature, and that record is what tells it the session is gone instead of
// leaving it to guess. Sessions are held in a fixed 256-slot array, so scanning
// them all costs nothing and needs no second index to drift out of step.
func (s *sessionStore) CloseUserSessions(user *userAccount, now time.Time, closedRetention time.Duration) []closedSessionCleanup {
	if s == nil || user == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	closed := make([]closedSessionCleanup, 0, 4)
	for sessionID := 1; sessionID <= maxServerSessionID; sessionID++ {
		record := s.byID[sessionID]
		if record == nil || record.user != user {
			continue
		}

		delete(s.bySig, record.Signature)
		s.byID[sessionID] = nil
		if s.activeCount > 0 {
			s.activeCount--
		}
		if closedRetention > 0 {
			s.recentClosed[uint8(sessionID)] = closedSessionRecord{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				ExpiresAt:    now.Add(closedRetention),
			}
		}
		record.markClosed()
		closed = append(closed, closedSessionCleanup{
			ID:     uint8(sessionID),
			record: record,
		})
	}

	return closed
}

func (s *sessionStore) SweepTerminalStreams(now time.Time, retention time.Duration) {
	s.mu.RLock()
	records := make([]*sessionRecord, 0, len(s.byID))
	for _, record := range s.byID {
		if record != nil {
			records = append(records, record)
		}
	}
	s.mu.RUnlock()

	for _, record := range records {
		record.cleanupTerminalStreams(now, retention)
	}
}

func (s *sessionStore) SweepRecentlyClosedStreams(now time.Time) {
	s.mu.RLock()
	records := make([]*sessionRecord, 0, len(s.byID))
	for _, record := range s.byID {
		if record != nil {
			records = append(records, record)
		}
	}
	s.mu.RUnlock()

	for _, record := range records {
		record.pruneRecentlyClosed(now)
	}
}

// effectiveMaxActiveSessions is the table's size: the configured limit,
// within the 255 an 8-bit session ID allows.
func (s *sessionStore) effectiveMaxActiveSessions() int {
	if s.maxActiveSessions <= 0 || s.maxActiveSessions > maxServerSessionSlots {
		return maxServerSessionSlots
	}
	return s.maxActiveSessions
}

func (s *sessionStore) allocateSlotLocked() int {
	maxActiveSessions := s.effectiveMaxActiveSessions()

	if s.activeCount >= uint16(maxActiveSessions) {
		return -1
	}

	start := int(s.nextID)
	if start < 1 || start > maxServerSessionID {
		start = 1
	}
	for slot := start; slot <= maxServerSessionID; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	for slot := 1; slot < start; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	return -1
}

func (s *sessionStore) randomCookieLocked() uint8 {
	if s.cookieIndex >= len(s.cookieBytes) {
		if _, err := rand.Read(s.cookieBytes[:]); err != nil {
			s.cookieIndex = len(s.cookieBytes)
			return 0
		}
		s.cookieIndex = 0
	}
	value := s.cookieBytes[s.cookieIndex]
	s.cookieIndex++
	return value
}

func (s *sessionStore) updateNextReuseSweepLocked(reuseUntilUnixNano int64) {
	if s.nextReuseSweepUnixNano == 0 || reuseUntilUnixNano < s.nextReuseSweepUnixNano {
		s.nextReuseSweepUnixNano = reuseUntilUnixNano
	}
}

func clampMTU(value uint16) uint16 {
	if value < minSessionMTU {
		return minSessionMTU
	}

	if value > maxSessionMTU {
		return maxSessionMTU
	}

	return value
}

func isValidSessionResponseMode(value uint8) bool {
	return value <= mtuProbeModeBase64
}

func (r *sessionRecord) setLastActivity(now time.Time) {
	r.setLastActivityUnixNano(now.UnixNano())
}

func (r *sessionRecord) setLastActivityUnixNano(nowUnixNano int64) {
	atomic.StoreInt64(&r.lastActivityUnixNano, nowUnixNano)
}

func (r *sessionRecord) lastActivity() int64 {
	return atomic.LoadInt64(&r.lastActivityUnixNano)
}

func (s *sessionStore) CollectIdleDeferredSessions(now time.Time, idleTimeout time.Duration) []idleDeferredCleanup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if idleTimeout <= 0 {
		return nil
	}

	nowUnixNano := now.UnixNano()
	idleTimeoutNanos := idleTimeout.Nanoseconds()
	idle := make([]idleDeferredCleanup, 0, 4)

	for sessionID := 1; sessionID <= maxServerSessionID; sessionID++ {
		record := s.byID[sessionID]
		if record == nil || record.isClosed() {
			continue
		}

		lastActivityUnixNano := record.lastActivity()
		if lastActivityUnixNano == 0 || nowUnixNano-lastActivityUnixNano < idleTimeoutNanos {
			continue
		}
		if record.lastDeferredCleanupActivity() == lastActivityUnixNano {
			continue
		}

		record.markDeferredCleanupActivity(lastActivityUnixNano)
		idle = append(idle, idleDeferredCleanup{
			ID:               uint8(sessionID),
			lastActivityNano: lastActivityUnixNano,
		})
	}

	return idle
}

func (r *sessionRecord) lastDeferredCleanupActivity() int64 {
	return atomic.LoadInt64(&r.lastDeferredCleanupActivityUnixNano)
}

func (r *sessionRecord) markDeferredCleanupActivity(activityUnixNano int64) {
	atomic.StoreInt64(&r.lastDeferredCleanupActivityUnixNano, activityUnixNano)
}

func nextSessionID(current uint8) uint8 {
	if current >= maxServerSessionID {
		return 1
	}
	return current + 1
}

func (r *sessionRecord) applyMTUFromSessionInit(
	uploadMTU uint16,
	downloadMTU uint16,
	maxPacketsPerBatch int,
	maxClientUploadMTU int,
	maxClientDownloadMTU int,
) {
	if r == nil {
		return
	}

	effectiveUploadMax := clampSessionInitAllowedMTU(maxClientUploadMTU)
	effectiveDownloadMax := clampSessionInitAllowedMTU(maxClientDownloadMTU)

	r.UploadMTU = clampMTUToLimit(uploadMTU, effectiveUploadMax)
	r.DownloadMTU = clampMTUToLimit(downloadMTU, effectiveDownloadMax)
	r.DownloadMTUBytes = int(r.DownloadMTU)
	if r.v2 {
		// The client measured how large a response gets through; sealing adds
		// a nonce and a tag to every one, so the payload must shrink by that.
		r.DownloadMTUBytes = max(r.DownloadMTUBytes-sessioncrypto.DownOverhead, minSessionMTU)
	}
	r.MaxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(r.DownloadMTUBytes, 80, maxPacketsPerBatch)
}

func clampMTUToLimit(value uint16, maxAllowed uint16) uint16 {
	clamped := clampMTU(value)
	if clamped > maxAllowed {
		return maxAllowed
	}
	return clamped
}

func clampSessionInitAllowedMTU(value int) uint16 {
	if value < minSessionMTU {
		return minSessionMTU
	}
	if value > maxSessionMTU {
		return maxSessionMTU
	}
	return uint16(value)
}

func (r *sessionRecord) runtimeView() sessionRuntimeView {
	return sessionRuntimeView{
		user:                r.user,
		v2:                  r.v2,
		keys:                r.keys,
		deviceAddr:          r.deviceAddr,
		ID:                  r.ID,
		Cookie:              r.Cookie,
		ResponseMode:        r.ResponseMode,
		ResponseBase64:      r.ResponseMode == mtuProbeModeBase64,
		DownloadCompression: r.DownloadCompression,
		DownloadMTU:         r.DownloadMTU,
		DownloadMTUBytes:    r.DownloadMTUBytes,
		MaxPackedBlocks:     r.MaxPackedBlocks,
	}
}

func (r *sessionRecord) markClosed() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 1)
}

func (r *sessionRecord) reopen() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 0)
}

func (r *sessionRecord) isClosed() bool {
	if r == nil {
		return true
	}
	return atomic.LoadUint32(&r.closedFlag) != 0
}

// ensureStream0 creates correctly virtual stream 0 if not exist
func (r *sessionRecord) ensureStream0(logger arq.Logger) {
	if r == nil || r.isClosed() {
		return
	}
	r.getOrCreateStream(0, arq.Config{IsVirtual: true}, nil, logger)
}

func (r *sessionRecord) getOrCreateStream(streamID uint16, arqConfig arq.Config, localConn io.ReadWriteCloser, logger arq.Logger) *Stream_server {
	if r == nil || r.isClosed() {
		return nil
	}

	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()
	if r.isClosed() {
		return nil
	}

	if s, ok := r.Streams[streamID]; ok {
		return s
	}

	if !r.canCreateAdditionalStreamLocked(streamID) {
		return nil
	}

	delete(r.RecentlyClosed, streamID)

	s := NewStreamServer(streamID, r.ID, arqConfig, localConn, r.DownloadMTUBytes, r.StreamQueueCap, logger)
	s.onClosed = r.onStreamClosed
	r.Streams[streamID] = s

	// Active streams tracking: keep sorted for Round-Robin predictability
	found := slices.Contains(r.ActiveStreams, streamID)
	if !found {
		// Insert sorted
		insertAt := 0
		for i, id := range r.ActiveStreams {
			if id > streamID {
				insertAt = i
				break
			}
			insertAt = i + 1
		}
		if insertAt == len(r.ActiveStreams) {
			r.ActiveStreams = append(r.ActiveStreams, streamID)
		} else {
			r.ActiveStreams = append(r.ActiveStreams[:insertAt+1], r.ActiveStreams[insertAt:]...)
			r.ActiveStreams[insertAt] = streamID
		}
		r.markActiveStreamsChangedLocked()
	}

	return s
}

func (r *sessionRecord) canCreateAdditionalStream(streamID uint16) bool {
	if r == nil || r.isClosed() {
		return false
	}

	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()
	return r.canCreateAdditionalStreamLocked(streamID)
}

func (r *sessionRecord) canCreateAdditionalStreamLocked(streamID uint16) bool {
	if streamID == 0 {
		return true
	}
	if _, exists := r.Streams[streamID]; exists {
		return true
	}

	limit := r.MaxActiveStreamsPerSession
	if limit <= 0 {
		limit = 2000
	}

	activeStreams := len(r.Streams)
	if _, exists := r.Streams[0]; exists {
		activeStreams--
	}

	return activeStreams < limit
}

func shouldSuppressServerOrphanForCloseReason(reason string) bool {
	return strings.Contains(reason, "close handshake completed") ||
		strings.HasSuffix(reason, "acknowledged")
}

func (r *sessionRecord) onStreamClosed(streamID uint16, now time.Time, reason string) {
	if r == nil || streamID == 0 {
		return
	}
	r.removeStream(streamID, now, shouldSuppressServerOrphanForCloseReason(reason))
	if r.streamCleanup != nil {
		r.streamCleanup(r.ID, streamID)
	}
}

func (r *sessionRecord) getStream(streamID uint16) (*Stream_server, bool) {
	if r == nil || r.isClosed() {
		return nil, false
	}
	r.StreamsMu.RLock()
	s, ok := r.Streams[streamID]
	r.StreamsMu.RUnlock()
	return s, ok
}
func (r *sessionRecord) noteStreamClosed(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	r.pruneRecentlyClosedLocked(now)

	r.RecentlyClosed[streamID] = recentlyClosedStreamRecord{
		ClosedAt:       now,
		SuppressOrphan: suppressOrphan,
	}
	heap.Push(&r.RecentlyClosedHeap, recentlyClosedEntry{streamID: streamID, closedAt: now})

	// Cap the map size
	r.evictOldestRecentlyClosedLocked()
}

func (r *sessionRecord) pruneRecentlyClosed(now time.Time) {
	if r == nil || r.isClosed() {
		return
	}
	r.StreamsMu.Lock()
	r.pruneRecentlyClosedLocked(now)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) pruneRecentlyClosedLocked(now time.Time) {
	if r == nil {
		return
	}
	expiredBefore := now.Add(-r.closedStreamRecordTTL())
	for len(r.RecentlyClosedHeap) > 0 {
		entry := r.RecentlyClosedHeap[0]
		record, ok := r.RecentlyClosed[entry.streamID]
		if !ok || !record.ClosedAt.Equal(entry.closedAt) {
			heap.Pop(&r.RecentlyClosedHeap)
			continue
		}

		if record.ClosedAt.Before(expiredBefore) {
			delete(r.RecentlyClosed, entry.streamID)
			heap.Pop(&r.RecentlyClosedHeap)
			continue
		}
		break
	}
}

func (r *sessionRecord) evictOldestRecentlyClosedLocked() {
	capacity := r.closedStreamRecordCap()
	for len(r.RecentlyClosed) > capacity && len(r.RecentlyClosedHeap) > 0 {
		entry := heap.Pop(&r.RecentlyClosedHeap).(recentlyClosedEntry)
		record, ok := r.RecentlyClosed[entry.streamID]
		if !ok || !record.ClosedAt.Equal(entry.closedAt) {
			continue
		}

		delete(r.RecentlyClosed, entry.streamID)
	}
}

func (r *sessionRecord) isRecentlyClosed(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL()
}

func (r *sessionRecord) shouldSuppressOrphanForClosedStream(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL() && record.SuppressOrphan
}

func (r *sessionRecord) closedStreamRecordTTL() time.Duration {
	if r == nil || r.RecentlyClosedTTL <= 0 {
		return 600 * time.Second
	}
	return r.RecentlyClosedTTL
}

func (r *sessionRecord) closedStreamRecordCap() int {
	if r == nil || r.RecentlyClosedCap < 1 {
		return 2000
	}
	return r.RecentlyClosedCap
}

func (r *sessionRecord) removeStream(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	delete(r.Streams, streamID)

	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()

	r.noteStreamClosed(streamID, now, suppressOrphan)
}

func (r *sessionRecord) deactivateStream(streamID uint16) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}

	r.StreamsMu.Lock()
	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) removeActiveStreamLocked(streamID uint16) {
	for i, id := range r.ActiveStreams {
		if id == streamID {
			r.ActiveStreams = append(r.ActiveStreams[:i], r.ActiveStreams[i+1:]...)
			r.markActiveStreamsChangedLocked()
			break
		}
	}
}

func (r *sessionRecord) markActiveStreamsChangedLocked() {
	r.activeStreamSetVersion++
}

func (r *sessionRecord) activeStreamSnapshot() ([]int32, []*Stream_server) {
	if r == nil || r.isClosed() {
		return nil, nil
	}

	r.StreamsMu.RLock()
	version := r.activeStreamSetVersion
	if version == r.activeStreamSnapshotVersion {
		ids := r.activeStreamSnapshotIDs
		streams := r.activeStreamSnapshotStreams
		r.StreamsMu.RUnlock()
		return ids, streams
	}
	r.StreamsMu.RUnlock()

	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	if r.activeStreamSetVersion != r.activeStreamSnapshotVersion {
		snapshotIDs := make([]int32, len(r.ActiveStreams))
		snapshotStreams := make([]*Stream_server, len(r.ActiveStreams))
		for i, id := range r.ActiveStreams {
			snapshotIDs[i] = int32(id)
			snapshotStreams[i] = r.Streams[id]
		}
		r.activeStreamSnapshotIDs = snapshotIDs
		r.activeStreamSnapshotStreams = snapshotStreams
		r.activeStreamSnapshotVersion = r.activeStreamSetVersion
	}

	return r.activeStreamSnapshotIDs, r.activeStreamSnapshotStreams
}

func (r *sessionRecord) closeAllStreams(reason string) {
	if r == nil {
		return
	}
	r.markClosed()

	r.StreamsMu.RLock()
	streams := make([]*Stream_server, 0, len(r.Streams))
	for _, stream := range r.Streams {
		if stream != nil {
			streams = append(streams, stream)
		}
	}
	r.StreamsMu.RUnlock()

	for _, stream := range streams {
		if reason != "session closed cleanup" {
			stream.Abort(reason)
		} else if stream.ARQ != nil {
			stream.ARQ.Close(reason, arq.CloseOptions{Force: true})
		}

		stream.finalizeAfterARQClose(reason)
	}

	r.StreamsMu.Lock()
	clear(r.Streams)
	r.ActiveStreams = r.ActiveStreams[:0]
	r.markActiveStreamsChangedLocked()
	r.StreamsMu.Unlock()

	if r.OrphanQueue != nil {
		r.OrphanQueue.Clear(nil)
	}
}

func (r *sessionRecord) cleanupTerminalStreams(now time.Time, retention time.Duration) {
	if r == nil || r.isClosed() {
		return
	}

	r.StreamsMu.RLock()
	snapshot := make(map[uint16]*Stream_server, len(r.Streams))
	for id, stream := range r.Streams {
		snapshot[id] = stream
	}
	r.StreamsMu.RUnlock()

	var removeIDs []uint16
	for streamID, stream := range snapshot {
		if streamID == 0 || stream == nil || stream.ARQ == nil {
			continue
		}

		state := stream.ARQ.State()
		stream.mu.Lock()
		switch state {
		case arq.StateDraining:
			stream.Status = "DRAINING"
		case arq.StateHalfClosedLocal, arq.StateHalfClosedRemote, arq.StateClosing:
			stream.Status = "CLOSING"
		case arq.StateTimeWait:
			stream.Status = "TIME_WAIT"
		}

		forceClosedExpired := !stream.CloseTime.IsZero() && now.Sub(stream.CloseTime) >= retention
		if stream.ARQ.IsClosed() || forceClosedExpired {
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.Status = "TIME_WAIT"
			if forceClosedExpired || now.Sub(stream.CloseTime) >= retention {
				removeIDs = append(removeIDs, streamID)
			}
		}
		stream.mu.Unlock()
	}

	for _, streamID := range removeIDs {
		if stream, ok := snapshot[streamID]; ok && stream != nil {
			stream.Abort("terminal stream retention cleanup")
			stream.finalizeAfterARQClose("terminal stream retention cleanup")
		}
		r.removeStream(streamID, now, false)
	}
}

func orphanResetKey(packetType uint8, streamID uint16) uint64 {
	return Enums.PacketTypeStreamKey(streamID, packetType)
}

func (r *sessionRecord) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if r == nil || r.isClosed() || r.OrphanQueue == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	key := orphanResetKey(packetType, streamID)
	// Orphans have high priority (0).
	r.OrphanQueue.Push(0, key, packet)
}

// deviceKey is what this session's traffic is counted against as a device:
// the device the client declared (v2), or else the address the packet came
// from - which, for a DNS tunnel, is a recursive resolver's.
func (v *sessionRuntimeView) deviceKey(clientIP string) string {
	if v != nil && v.deviceAddr != "" {
		return v.deviceAddr
	}
	return clientIP
}
