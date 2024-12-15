// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package sntp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"

	"github.com/OpenPSG/sntp/types"
)

const (
	// The maximum number of rate limiters instances to keep track of.
	maxRateLimiters = 10000
	// The minimum interval between requests from a single client.
	minInterval = 10 * time.Second
)

type Server struct {
	rateLimiters *expirable.LRU[netip.Addr, *rate.Limiter]
}

func NewServer() *Server {
	return &Server{
		rateLimiters: expirable.NewLRU[netip.Addr, *rate.Limiter](maxRateLimiters, nil, 24*time.Hour),
	}
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("error resolving UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("error listening on UDP: %w", err)
	}
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		req := make([]byte, binary.Size(types.Packet{}))
		n, addr, err := conn.ReadFromUDP(req)
		recvTimestamp := time.Now()
		if err != nil {
			return fmt.Errorf("error reading from UDP: %w", err)
		}

		// Is the packet the correct size?
		if n < len(req) {
			slog.Warn("Received undersized packet", slog.Int("size", n))
			continue
		}

		// Is the client rate limited?
		if !s.checkRateLimit(addr) {
			slog.Warn("Rate limited client", slog.String("addr", addr.String()))
			// TODO: Send a kiss of death packet indicating the client is rate limited.
			continue
		}

		go s.handleRequest(conn, addr, req[:n], recvTimestamp)
	}
}

func (s *Server) handleRequest(conn *net.UDPConn, addr *net.UDPAddr, req []byte, recvTimestamp time.Time) {
	var clientRequest types.Packet
	if err := binary.Read(bytes.NewReader(req), binary.BigEndian, &clientRequest); err != nil {
		slog.Error("Error decoding request", slog.Any("error", err))
		return
	}

	if clientRequest.GetMode() != types.ModeClient || clientRequest.GetVersion() != types.Version4 {
		slog.Warn("Received invalid request", slog.Any("packet", clientRequest))
		// TODO: Send a kiss of death packet indicating the client is using an invalid mode or version.
		return
	}

	serverResponse := types.Packet{
		Stratum:       types.StratumPrimary,
		Poll:          clientRequest.Poll,
		Precision:     types.PrecisionOneMicrosecond,
		RefTimestamp:  toNTPTime(time.Now()), // TODO: Use a more accurate reference time.
		OrigTimestamp: clientRequest.XmitTimestamp,
		RecvTimestamp: toNTPTime(recvTimestamp),
	}

	serverResponse.SetMode(types.ModeServer)
	serverResponse.SetVersion(types.Version4)
	serverResponse.SetExternalReferenceSource(types.ExternalReferenceSourceLocal)

	var resp bytes.Buffer
	if err := binary.Write(&resp, binary.BigEndian, serverResponse); err != nil {
		slog.Error("Error encoding response", slog.Any("error", err))
		return
	}

	respBytes := resp.Bytes()

	// Populate the transmit timestamp at the last possible moment.
	binary.BigEndian.PutUint64(respBytes[40:], toNTPTime(time.Now()))

	// Send the response.
	if _, err := conn.WriteToUDP(respBytes, addr); err != nil {
		slog.Error("Error sending response", slog.Any("error", err))
		return
	}
}

func (s *Server) checkRateLimit(addr *net.UDPAddr) bool {
	ip, _ := netip.AddrFromSlice(addr.IP)

	limiter, ok := s.rateLimiters.Get(ip)
	if !ok {
		limiter = rate.NewLimiter(rate.Every(minInterval), 1)
		s.rateLimiters.Add(ip, limiter)
	}

	return limiter.Allow()
}

// toNTPTime converts a time.Time to an NTP timestamp (microsecond precision).
func toNTPTime(t time.Time) uint64 {
	const ntpEpochDelta = 2208988800 // Seconds between 1900-01-01 and 1970-01-01.
	secs := uint64(t.Unix() + int64(ntpEpochDelta))
	frac := uint64(t.Nanosecond()) * math.MaxUint32 / 1e9
	return secs<<32 | frac&0xFFFFF000 | nonce()
}

// nonce generates a random 12-bit nonce that is used to prevent a
// variety of off-path attacks against the NTP protocol.
func nonce() uint64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(1<<12))
	return v.Uint64()
}
