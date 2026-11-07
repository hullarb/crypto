// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/internal/sshzlib/zlib"
)

type packetCompression struct {
	writer *zlib.Writer
	reader *zlibPacketReader
	buf    bytes.Buffer
}

func newPacketCompression(name string) (*packetCompression, bool, error) {
	switch name {
	case compressionNone:
		return nil, false, nil
	case compressionZlib:
		return &packetCompression{
			reader: newZlibPacketReader(),
		}, false, nil
	case compressionZlibOpenSSH:
		return &packetCompression{
			reader: newZlibPacketReader(),
		}, true, nil
	default:
		return nil, false, fmt.Errorf("ssh: unsupported compression algorithm %q", name)
	}
}

func (c *packetCompression) compressPacket(packet []byte) ([]byte, error) {
	if c.writer == nil {
		c.writer = zlib.NewWriter(&c.buf)
	}
	c.buf.Reset()
	if _, err := c.writer.Write(packet); err != nil {
		return nil, err
	}
	if err := c.writer.PartialFlush(); err != nil {
		return nil, err
	}

	// The cipher layer mutates packet bytes in place, so return a fresh slice
	// detached from the reusable compression buffer.
	return append([]byte(nil), c.buf.Bytes()...), nil
}

func (c *packetCompression) decompressPacket(packet []byte) ([]byte, error) {
	return c.reader.ReadPacket(packet, maxPacket)
}
