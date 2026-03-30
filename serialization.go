package bulletproofs

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Point and scalar sizes derived from gnark-crypto library constants.
const (
	compressedG1Size = bn254.SizeOfG1AffineCompressed // 32 bytes
	scalarSize       = fr.Bytes                       // 32 bytes
)

// marshalCompressed serializes a G1 affine point to 32-byte compressed form.
func marshalCompressed(p *bn254.G1Affine) []byte {
	b := p.Bytes() // gnark-crypto compressed format, 32 bytes
	return b[:]
}

// unmarshalCompressed deserializes a 32-byte compressed G1 point.
func unmarshalCompressed(data []byte) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	_, err := p.SetBytes(data)
	return p, err
}

// marshalScalar serializes a field element to 32 bytes (big-endian).
func marshalScalar(s *fr.Element) []byte {
	b := s.Bytes() // 32 bytes, big-endian
	return b[:]
}

// unmarshalScalar deserializes a 32-byte field element.
func unmarshalScalar(data []byte) (fr.Element, error) {
	var s fr.Element
	err := s.SetBytesCanonical(data)
	return s, err
}

// Marshal serializes an IPProof to bytes.
//
// Layout: numRounds(4 bytes, uint32 big-endian) || L[0](32) || R[0](32) || ... || L[k](32) || R[k](32) || A(32) || B(32)
func (p *IPProof) Marshal() ([]byte, error) {
	k := len(p.L)
	if k != len(p.R) {
		return nil, errors.New("ipproof marshal: L and R must have same length")
	}

	// Total size: 4 + k*32 + k*32 + 32 + 32 = 4 + 64k + 64
	size := 4 + k*2*compressedG1Size + 2*scalarSize
	buf := make([]byte, 0, size)

	// numRounds
	var numRounds [4]byte
	binary.BigEndian.PutUint32(numRounds[:], uint32(k))
	buf = append(buf, numRounds[:]...)

	// L and R interleaved
	for i := 0; i < k; i++ {
		buf = append(buf, marshalCompressed(&p.L[i])...)
		buf = append(buf, marshalCompressed(&p.R[i])...)
	}

	// A and B scalars
	buf = append(buf, marshalScalar(&p.A)...)
	buf = append(buf, marshalScalar(&p.B)...)

	return buf, nil
}

// maxIPRounds is the maximum number of inner product rounds accepted during
// deserialization. log2(maxGeneratorN) = 20; we use a generous upper bound.
const maxIPRounds = 64

// Unmarshal deserializes an IPProof from bytes.
func (p *IPProof) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errors.New("ipproof unmarshal: data too short for header")
	}

	k := int(binary.BigEndian.Uint32(data[:4]))
	if k > maxIPRounds {
		return fmt.Errorf("ipproof unmarshal: numRounds %d exceeds maximum %d", k, maxIPRounds)
	}
	expectedSize := 4 + k*2*compressedG1Size + 2*scalarSize
	if len(data) < expectedSize {
		return fmt.Errorf("ipproof unmarshal: expected %d bytes, got %d", expectedSize, len(data))
	}

	offset := 4
	p.L = make([]bn254.G1Affine, k)
	p.R = make([]bn254.G1Affine, k)

	for i := 0; i < k; i++ {
		var err error
		p.L[i], err = unmarshalCompressed(data[offset : offset+compressedG1Size])
		if err != nil {
			return fmt.Errorf("ipproof unmarshal: L[%d]: %w", i, err)
		}
		offset += compressedG1Size

		p.R[i], err = unmarshalCompressed(data[offset : offset+compressedG1Size])
		if err != nil {
			return fmt.Errorf("ipproof unmarshal: R[%d]: %w", i, err)
		}
		offset += compressedG1Size
	}

	var err error
	p.A, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("ipproof unmarshal: A: %w", err)
	}
	offset += scalarSize

	p.B, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("ipproof unmarshal: B: %w", err)
	}

	return nil
}

// Marshal serializes a RangeProof to bytes.
//
// Layout: A(32) || S(32) || T1(32) || T2(32) || Taux(32) || Mu(32) || That(32) || IPProof
func (p *RangeProof) Marshal() ([]byte, error) {
	ipBytes, err := p.IP.Marshal()
	if err != nil {
		return nil, fmt.Errorf("rangeproof marshal: %w", err)
	}

	// Fixed header: 7 * 32 = 224 bytes
	size := 7*compressedG1Size + len(ipBytes)
	buf := make([]byte, 0, size)

	buf = append(buf, marshalCompressed(&p.A)...)
	buf = append(buf, marshalCompressed(&p.S)...)
	buf = append(buf, marshalCompressed(&p.T1)...)
	buf = append(buf, marshalCompressed(&p.T2)...)
	buf = append(buf, marshalScalar(&p.Taux)...)
	buf = append(buf, marshalScalar(&p.Mu)...)
	buf = append(buf, marshalScalar(&p.That)...)
	buf = append(buf, ipBytes...)

	return buf, nil
}

// Unmarshal deserializes a RangeProof from bytes.
func (p *RangeProof) Unmarshal(data []byte) error {
	headerSize := 7 * compressedG1Size // 4 points + 3 scalars, all 32 bytes
	if len(data) < headerSize+4 {      // at least header + IP numRounds
		return errors.New("rangeproof unmarshal: data too short")
	}

	offset := 0
	var err error

	p.A, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: A: %w", err)
	}
	offset += compressedG1Size

	p.S, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: S: %w", err)
	}
	offset += compressedG1Size

	p.T1, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: T1: %w", err)
	}
	offset += compressedG1Size

	p.T2, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: T2: %w", err)
	}
	offset += compressedG1Size

	p.Taux, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: Taux: %w", err)
	}
	offset += scalarSize

	p.Mu, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: Mu: %w", err)
	}
	offset += scalarSize

	p.That, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("rangeproof unmarshal: That: %w", err)
	}
	offset += scalarSize

	return p.IP.Unmarshal(data[offset:])
}

// Marshal serializes an AggregateRangeProof to bytes.
// Same layout as RangeProof (same fields).
func (p *AggregateRangeProof) Marshal() ([]byte, error) {
	ipBytes, err := p.IP.Marshal()
	if err != nil {
		return nil, fmt.Errorf("aggregate rangeproof marshal: %w", err)
	}

	size := 7*compressedG1Size + len(ipBytes)
	buf := make([]byte, 0, size)

	buf = append(buf, marshalCompressed(&p.A)...)
	buf = append(buf, marshalCompressed(&p.S)...)
	buf = append(buf, marshalCompressed(&p.T1)...)
	buf = append(buf, marshalCompressed(&p.T2)...)
	buf = append(buf, marshalScalar(&p.Taux)...)
	buf = append(buf, marshalScalar(&p.Mu)...)
	buf = append(buf, marshalScalar(&p.That)...)
	buf = append(buf, ipBytes...)

	return buf, nil
}

// Unmarshal deserializes an AggregateRangeProof from bytes.
func (p *AggregateRangeProof) Unmarshal(data []byte) error {
	headerSize := 7 * compressedG1Size
	if len(data) < headerSize+4 {
		return errors.New("aggregate rangeproof unmarshal: data too short")
	}

	offset := 0
	var err error

	p.A, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: A: %w", err)
	}
	offset += compressedG1Size

	p.S, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: S: %w", err)
	}
	offset += compressedG1Size

	p.T1, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: T1: %w", err)
	}
	offset += compressedG1Size

	p.T2, err = unmarshalCompressed(data[offset : offset+compressedG1Size])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: T2: %w", err)
	}
	offset += compressedG1Size

	p.Taux, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: Taux: %w", err)
	}
	offset += scalarSize

	p.Mu, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: Mu: %w", err)
	}
	offset += scalarSize

	p.That, err = unmarshalScalar(data[offset : offset+scalarSize])
	if err != nil {
		return fmt.Errorf("aggregate rangeproof unmarshal: That: %w", err)
	}
	offset += scalarSize

	return p.IP.Unmarshal(data[offset:])
}

// Marshal serializes a ThresholdProof to bytes (delegates to inner RangeProof).
func (p *ThresholdProof) Marshal() ([]byte, error) {
	return p.Proof.Marshal()
}

// Unmarshal deserializes a ThresholdProof from bytes.
func (p *ThresholdProof) Unmarshal(data []byte) error {
	return p.Proof.Unmarshal(data)
}
