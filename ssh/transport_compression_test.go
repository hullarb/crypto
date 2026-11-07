// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"testing"
)

func testConnectionState(t *testing.T, compressionName string) connectionState {
	t.Helper()

	compression, delayed, err := newPacketCompression(compressionName)
	if err != nil {
		t.Fatal(err)
	}
	if delayed {
		t.Fatalf("testConnectionState called with delayed compression %q", compressionName)
	}
	return connectionState{
		packetCipher:     &streamPacketCipher{cipher: noneCipher{}},
		compression:      compression,
		pendingKeyChange: make(chan transportState, 1),
	}
}

func TestTransportCompressionRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	writer := testConnectionState(t, compressionZlib)
	reader := testConnectionState(t, compressionZlib)

	payloads := [][]byte{
		[]byte{msgChannelData, 0, 0, 0, 1},
		append([]byte{msgChannelData, 0, 0, 0, 1}, bytes.Repeat([]byte("compressible transport payload "), 128)...),
		append([]byte{msgChannelWindowAdjust, 0, 0, 0, 1}, bytes.Repeat([]byte("history should carry across SSH packets "), 64)...),
	}

	for i, want := range payloads {
		if err := writer.writePacket(bufio.NewWriter(&wire), rand.Reader, append([]byte(nil), want...), false); err != nil {
			t.Fatalf("writePacket(%d): %v", i, err)
		}
		got, err := reader.readPacket(bufio.NewReader(&wire), false)
		if err != nil {
			t.Fatalf("readPacket(%d): %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d mismatch: got %x, want %x", i, got, want)
		}
	}
}

func TestTransportCompressionStartsAfterNewKeys(t *testing.T) {
	var wire bytes.Buffer
	writer := testConnectionState(t, compressionNone)
	reader := testConnectionState(t, compressionNone)

	writerCompression, delayed, err := newPacketCompression(compressionZlib)
	if err != nil {
		t.Fatal(err)
	}
	if delayed {
		t.Fatal("zlib should activate immediately")
	}
	readerCompression, delayed, err := newPacketCompression(compressionZlib)
	if err != nil {
		t.Fatal(err)
	}
	if delayed {
		t.Fatal("zlib should activate immediately")
	}
	writer.pendingKeyChange <- transportState{
		packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		compression:  writerCompression,
	}
	reader.pendingKeyChange <- transportState{
		packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		compression:  readerCompression,
	}

	if err := writer.writePacket(bufio.NewWriter(&wire), rand.Reader, []byte{msgNewKeys}, false); err != nil {
		t.Fatalf("writePacket(newkeys): %v", err)
	}
	got, err := reader.readPacket(bufio.NewReader(&wire), false)
	if err != nil {
		t.Fatalf("readPacket(newkeys): %v", err)
	}
	if !bytes.Equal(got, []byte{msgNewKeys}) {
		t.Fatalf("newkeys mismatch: got %x", got)
	}

	payload := append([]byte{msgChannelData, 0, 0, 0, 1}, bytes.Repeat([]byte("after newkeys "), 128)...)
	if err := writer.writePacket(bufio.NewWriter(&wire), rand.Reader, append([]byte(nil), payload...), false); err != nil {
		t.Fatalf("writePacket(compressed): %v", err)
	}
	got, err = reader.readPacket(bufio.NewReader(&wire), false)
	if err != nil {
		t.Fatalf("readPacket(compressed): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("compressed payload mismatch: got %x, want %x", got, payload)
	}
}

func TestTransportDelayedCompressionStartsAfterAuth(t *testing.T) {
	tr := newTransport(&closerBuffer{}, rand.Reader, true)

	compression, delayed, err := newPacketCompression(compressionZlibOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	if !delayed {
		t.Fatal("zlib@openssh.com should be delayed")
	}
	tr.writer.pendingKeyChange <- transportState{
		packetCipher:       &streamPacketCipher{cipher: noneCipher{}},
		compression:        compression,
		delayedCompression: delayed,
	}

	if err := tr.writer.writePacket(bufio.NewWriter(&closerBuffer{}), rand.Reader, []byte{msgNewKeys}, false); err != nil {
		t.Fatalf("writePacket(newkeys): %v", err)
	}
	if tr.writer.compression != nil {
		t.Fatal("zlib@openssh.com activated before authentication")
	}
	if tr.writer.delayedCompression == nil {
		t.Fatal("zlib@openssh.com delayed compression was not retained")
	}

	tr.setAuthCompleted()
	if tr.writer.compression == nil {
		t.Fatal("zlib@openssh.com did not activate after authentication")
	}
	if tr.writer.delayedCompression != nil {
		t.Fatal("delayed compression retained after activation")
	}
}

func TestHandshakeDelayedCompression(t *testing.T) {
	a, b, err := netPipe()
	if err != nil {
		t.Fatal(err)
	}

	clientConfig := &ClientConfig{
		Config: Config{
			Compression: []string{CompressionZlibOpenSSH, CompressionNone},
		},
		HostKeyCallback: FixedHostKey(testSigners["ecdsa"].PublicKey()),
	}
	clientConfig.SetDefaults()

	serverConfig := &ServerConfig{
		Config: Config{
			Compression: []string{CompressionZlibOpenSSH, CompressionNone},
		},
	}
	serverConfig.AddHostKey(testSigners["ecdsa"])
	serverConfig.SetDefaults()

	v := []byte("version")
	clientTransport := newTransport(a, rand.Reader, true)
	serverTransport := newTransport(b, rand.Reader, false)
	client := newClientTransport(clientTransport, v, v, clientConfig, "addr", a.RemoteAddr())
	server := newServerTransport(serverTransport, v, v, serverConfig)

	if err := server.waitSession(); err != nil {
		t.Fatalf("server waitSession: %v", err)
	}
	if err := client.waitSession(); err != nil {
		t.Fatalf("client waitSession: %v", err)
	}
	defer client.Close()
	defer server.Close()

	if client.algorithms.Load().Read.compression != CompressionZlibOpenSSH || client.algorithms.Load().Write.compression != CompressionZlibOpenSSH {
		t.Fatalf("client negotiated compression r=%q w=%q", client.algorithms.Load().Read.compression, client.algorithms.Load().Write.compression)
	}
	if clientTransport.reader.compression != nil || clientTransport.writer.compression != nil ||
		serverTransport.reader.compression != nil || serverTransport.writer.compression != nil {
		t.Fatal("zlib@openssh.com activated before authentication")
	}
	if clientTransport.reader.delayedCompression == nil || clientTransport.writer.delayedCompression == nil ||
		serverTransport.reader.delayedCompression == nil || serverTransport.writer.delayedCompression == nil {
		t.Fatal("zlib@openssh.com was not retained for delayed activation")
	}

	if err := server.writePacket([]byte{msgUserAuthSuccess}); err != nil {
		t.Fatalf("server write auth success: %v", err)
	}
	var packet []byte
	for {
		packet, err = client.readPacket()
		if err != nil {
			t.Fatalf("client read auth success: %v", err)
		}
		if packet[0] != msgExtInfo {
			break
		}
	}
	if !bytes.Equal(packet, []byte{msgUserAuthSuccess}) {
		t.Fatalf("auth success packet = %x", packet)
	}

	if clientTransport.reader.compression == nil || clientTransport.writer.compression == nil ||
		serverTransport.reader.compression == nil || serverTransport.writer.compression == nil {
		t.Fatal("zlib@openssh.com did not activate after authentication")
	}

	clientPayload := append([]byte{msgChannelData, 0, 0, 0, 1}, bytes.Repeat([]byte("client payload "), 128)...)
	if err := client.writePacket(clientPayload); err != nil {
		t.Fatalf("client write compressed payload: %v", err)
	}
	packet, err = server.readPacket()
	if err != nil {
		t.Fatalf("server read compressed payload: %v", err)
	}
	if !bytes.Equal(packet, clientPayload) {
		t.Fatalf("server got %x, want %x", packet, clientPayload)
	}

	serverPayload := append([]byte{msgChannelData, 0, 0, 0, 2}, bytes.Repeat([]byte("server payload "), 128)...)
	if err := server.writePacket(serverPayload); err != nil {
		t.Fatalf("server write compressed payload: %v", err)
	}
	packet, err = client.readPacket()
	if err != nil {
		t.Fatalf("client read compressed payload: %v", err)
	}
	if !bytes.Equal(packet, serverPayload) {
		t.Fatalf("client got %x, want %x", packet, serverPayload)
	}
}
