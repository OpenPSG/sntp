// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package sntp_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/beevik/ntp"
	"github.com/stretchr/testify/require"

	"github.com/OpenPSG/sntp"
)

func TestSNTPServer(t *testing.T) {
	srv := sntp.NewServer()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := srv.ListenAndServe(ctx, "localhost:1230"); err != nil {
			slog.Error("Error serving NTP requests", slog.Any("error", err))
		}
	}()

	// Wait for the server to start.
	time.Sleep(100 * time.Millisecond)

	ntpTime, err := ntp.Time("localhost:1230")
	require.NoError(t, err)

	// Check that the retrieved time is within a second of the current time.
	require.WithinDuration(t, time.Now(), ntpTime, time.Second)
}
