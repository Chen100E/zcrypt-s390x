package codec

import (
	"encoding/binary"
	"errors"
	"math"
)

// MainframePacket represents an encoded binary payload.
type MainframePacket struct {
	Magic      uint32
	Timestamp  int64
	FloatVal   float64
	PayloadLen uint32
	Payload    []byte
}

// Encode serializes packet with strict Big-Endian byte ordering.
func (p *MainframePacket) Encode() []byte {
	buf := make([]byte, 24+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], p.Magic)
	binary.BigEndian.PutUint64(buf[4:12], uint64(p.Timestamp))
	binary.BigEndian.PutUint64(buf[12:20], math.Float64bits(p.FloatVal))
	binary.BigEndian.PutUint32(buf[20:24], uint32(len(p.Payload)))
	copy(buf[24:], p.Payload)
	return buf
}

// Decode deserializes binary buffer ensuring endianness integrity.
func Decode(buf []byte) (*MainframePacket, error) {
	if len(buf) < 24 {
		return nil, errors.New("buffer underflow: minimum 24 bytes required")
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	ts := int64(binary.BigEndian.Uint64(buf[4:12]))
	fbits := binary.BigEndian.Uint64(buf[12:20])
	val := math.Float64frombits(fbits)
	pLen := binary.BigEndian.Uint32(buf[20:24])

	if len(buf[24:]) < int(pLen) {
		return nil, errors.New("payload length mismatch")
	}

	return &MainframePacket{
		Magic:      magic,
		Timestamp:  ts,
		FloatVal:   val,
		PayloadLen: pLen,
		Payload:    buf[24 : 24+pLen],
	}, nil
}
