// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import "testing"

// This partial-flush payload stalls a reader attached to an open network
// stream: https://github.com/mjl-/flate/issues/1. SSH supplies a bounded packet,
// allowing the inflater to return all available output at the input boundary.
func TestPacketReaderPartialFlushIssue1(t *testing.T) {
	const compressed = "r4Q\xf0s\xf4u\r\x0eptv\xe5\xe5r4U\xf0\xf1\f\x0eQPRRP\xd2RR\br\r\t\r\xf2S\xd0\b\x0eq\f\t\rV\xd0\x00\xaa\vvtw\rV\b\xf5t\xf1s\x8d\b\x01\xd1a\x8e>\x9e.\x9e!\x91\n\xa1~\xc1\xae\xae~\n\x1e\x9e\xee\x1e\xae\xc1!\xbe\xfe.\xc1\xae\x81\x9a\n\xc1\x01\xaeΞ\x8e>\xba\xa1\xc1\xae\x9a\xbc\\\x00\x01"
	const want = "A4 NAMESPACE\r\nA5 LIST \"\" \"*\" RETURN (STATUS (MESSAGES UIDNEXT UIDVALIDITY UNSEEN HIGHESTMODSEQ) SPECIAL-USE)\r\n"
	for _, tc := range []struct {
		name    string
		read    func([]byte, int) ([]byte, error)
		payload []byte
	}{
		{"flate", newFlatePacketReader().ReadPacket, []byte(compressed)},
		{"zlib", newZlibPacketReader().ReadPacket, append([]byte{0x78, 0x9c}, []byte(compressed)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.read(tc.payload, maxPacket)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("ReadPacket = %q, want %q", got, want)
			}
		})
	}
}
