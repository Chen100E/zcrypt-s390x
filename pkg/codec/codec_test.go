package codec

import (
	"bytes"
	"testing"
)

func TestPacketSerialization(t *testing.T) {
	original := &MainframePacket{
		Magic:     0x5A435250, // "ZCRP"
		Timestamp: 1793439531,
		FloatVal:  123456.7890123,
		Payload:   []byte("IBM LinuxONE zSystems CPACF High-Throughput Stream"),
	}

	encoded := original.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Magic != original.Magic || decoded.Timestamp != original.Timestamp || decoded.FloatVal != original.FloatVal {
		t.Fatalf("Packet data corruption: got %+v, want %+v", decoded, original)
	}

	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Fatalf("Payload mismatch: got %s, want %s", decoded.Payload, original.Payload)
	}
}
