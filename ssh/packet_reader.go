// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"hash/adler32"
	"io"

	"golang.org/x/crypto/internal/sshzlib/flate"
	"golang.org/x/crypto/internal/sshzlib/zlib"
)

// errDecompressedSize is returned when a packet expands beyond the caller's
// configured limit.
var errDecompressedSize = errors.New("flate: decompressed packet too large")

// flatePacketReader inflates a continuous DEFLATE stream one packet payload at a
// time. It treats the end of each packet's compressed bytes as a resumable input
// boundary rather than as a corrupt truncated stream.
type flatePacketReader struct {
	src bytes.Reader
	f   io.ReadCloser
}

// newFlatePacketReader creates a packet-delimited DEFLATE reader.
func newFlatePacketReader() *flatePacketReader {
	return newFlatePacketReaderDict(nil)
}

// newFlatePacketReaderDict creates a packet-delimited DEFLATE reader initialized
// with a preset dictionary.
func newFlatePacketReaderDict(dict []byte) *flatePacketReader {
	r := &flatePacketReader{}
	r.ResetDict(dict)
	return r
}

// Reset resets r to read a new packet-delimited DEFLATE stream.
func (r *flatePacketReader) Reset() {
	r.ResetDict(nil)
}

// ResetDict resets r to read a new packet-delimited DEFLATE stream initialized
// with a preset dictionary.
func (r *flatePacketReader) ResetDict(dict []byte) {
	r.src.Reset(nil)
	r.f = flate.NewPartialReader(&r.src, dict)
}

// ReadPacket inflates one compressed packet payload. If limit is positive and
// the decompressed packet grows beyond it, ReadPacket returns errDecompressedSize.
func (r *flatePacketReader) ReadPacket(packet []byte, limit int) ([]byte, error) {
	r.src.Reset(packet)

	var out bytes.Buffer
	var buf [32 * 1024]byte
	for {
		n, err := r.f.Read(buf[:])
		if n > 0 {
			if limit > 0 && out.Len()+n > limit {
				return nil, errDecompressedSize
			}
			out.Write(buf[:n])
		}
		switch err {
		case nil:
			continue
		case flate.ErrNeedMoreInput:
			return out.Bytes(), nil
		default:
			return out.Bytes(), err
		}
	}
}

// zlibPacketReader inflates a zlib-framed DEFLATE stream one SSH packet payload at
// a time. It does not require the zlib checksum trailer, because SSH
// compression keeps the zlib stream open across packets.
type zlibPacketReader struct {
	inflater *flatePacketReader
	digest   hash.Hash32
	header   []byte
	started  bool
}

// newZlibPacketReader creates a packet-delimited zlib reader.
func newZlibPacketReader() *zlibPacketReader {
	r := &zlibPacketReader{}
	r.Reset()
	return r
}

// Reset resets r to read a new packet-delimited zlib stream.
func (r *zlibPacketReader) Reset() {
	r.inflater = newFlatePacketReader()
	r.digest = adler32.New()
	r.header = nil
	r.started = false
}

// ReadPacket inflates one compressed zlib packet payload. If limit is positive
// and the decompressed packet grows beyond it, ReadPacket returns
// errDecompressedSize.
func (r *zlibPacketReader) ReadPacket(packet []byte, limit int) ([]byte, error) {
	if !r.started {
		var err error
		packet, err = r.start(packet)
		if err != nil {
			return nil, err
		}
		if !r.started {
			return nil, nil
		}
	}

	out, err := r.inflater.ReadPacket(packet, limit)
	if len(out) > 0 {
		r.digest.Write(out)
	}
	return out, err
}

func (r *zlibPacketReader) start(packet []byte) ([]byte, error) {
	if len(r.header) > 0 || len(packet) < 2 {
		r.header = append(r.header, packet...)
		if len(r.header) < 2 {
			return nil, nil
		}
		packet = r.header
		r.header = nil
	}

	const (
		zlibDeflate   = 8
		zlibMaxWindow = 7
	)
	h := binary.BigEndian.Uint16(packet[:2])
	if (packet[0]&0x0f != zlibDeflate) || (packet[0]>>4 > zlibMaxWindow) || (h%31 != 0) {
		return nil, zlib.ErrHeader
	}
	if packet[1]&0x20 != 0 {
		return nil, zlib.ErrDictionary
	}

	r.started = true
	return packet[2:], nil
}
