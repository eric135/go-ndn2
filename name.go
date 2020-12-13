/* GoNDN2 - NDN Forwarder Library for Go
 *
 * Copyright (C) 2020 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package ndn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/eric135/go-ndn2/tlv"
	"github.com/eric135/go-ndn2/util"
)

// NameComponent represents an NDN name component.
type NameComponent interface {
	String() string
	DeepCopy() NameComponent
	Type() uint16
	Value() []byte
	Wire() *tlv.Block
}

// DecodeNameComponent decodes a name component from the wire.
func DecodeNameComponent(wire *tlv.Block) (NameComponent, error) {
	if wire == nil {
		return nil, util.ErrNonExistent
	}
	if len(wire.Value()) == 0 {
		return nil, tlv.ErrBufferTooShort
	}

	var n NameComponent
	var err error
	switch wire.Type() {
	case tlv.ImplicitSha256DigestComponent:
		n, err = NewImplicitSha256DigestComponent(wire.Value())
	case tlv.ParametersSha256DigestComponent:
		n, err = NewParametersSha256DigestComponent(wire.Value())
	case tlv.GenericNameComponent:
		n, err = NewGenericNameComponent(wire.Value())
	case tlv.KeywordNameComponent:
		n, err = NewKeywordNameComponent(wire.Value())
	case tlv.SegmentNameComponent:
		n, err = NewSegmentNameComponent(binary.BigEndian.Uint64(wire.Value()))
	case tlv.ByteOffsetNameComponent:
		n, err = NewByteOffsetNameComponent(binary.BigEndian.Uint64(wire.Value()))
	case tlv.VersionNameComponent:
		n, err = NewVersionNameComponent(binary.BigEndian.Uint64(wire.Value()))
	case tlv.TimestampNameComponent:
		n, err = NewTimestampNameComponent(binary.BigEndian.Uint64(wire.Value()))
	case tlv.SequenceNumNameComponent:
		n, err = NewSequenceNumNameComponent(binary.BigEndian.Uint64(wire.Value()))
	default:
		if wire.Type() > math.MaxUint16 {
			n = nil
			err = util.ErrOutOfRange
		} else {
			n, err = NewBaseNameComponent(uint16(wire.Type()), wire.Value())
		}
	}
	return n, err
}

////////////////////
// BaseNameComponent
////////////////////

// BaseNameComponent represents a name component without a specialized type.
type BaseNameComponent struct {
	tlvType uint16
	value   []byte
	wire    *tlv.Block
}

// NewBaseNameComponent creates a name component of an arbitrary type.
func NewBaseNameComponent(tlvType uint16, value []byte) (*BaseNameComponent, error) {
	if len(value) == 0 {
		return nil, util.ErrTooShort
	}

	n := new(BaseNameComponent)
	n.tlvType = tlvType
	n.value = make([]byte, len(value))
	copy(n.value, value)
	return n, nil
}

func (n *BaseNameComponent) String() string {
	return strconv.FormatUint(uint64(n.tlvType), 10) + "=" + string(n.value)
}

// DeepCopy makes a deep copy of the name component.
func (n *BaseNameComponent) DeepCopy() NameComponent {
	newN := new(BaseNameComponent)
	newN.tlvType = n.tlvType
	newN.value = make([]byte, len(n.value))
	copy(newN.value, n.value)
	return newN
}

// Type returns the TLV type of the name component.
func (n *BaseNameComponent) Type() uint16 {
	return n.tlvType
}

// Value returns the TLV value of the name component.
func (n *BaseNameComponent) Value() []byte {
	return n.value
}

// Wire encodes the name component into its wire encoding.
func (n *BaseNameComponent) Wire() *tlv.Block {
	if n.wire == nil || !n.wire.HasWire() {
		n.wire = tlv.NewBlock(uint32(n.tlvType), n.value)
	}
	return n.wire.DeepCopy()
}

////////////////////////////////
// ImplicitSha256DigestComponent
////////////////////////////////

// ImplicitSha256DigestComponent represents an implicit SHA-256 digest component.
type ImplicitSha256DigestComponent struct {
	BaseNameComponent
}

// NewImplicitSha256DigestComponent creates a new ImplicitSha256DigestComponent.
func NewImplicitSha256DigestComponent(value []byte) (*ImplicitSha256DigestComponent, error) {
	if len(value) != 32 {
		return nil, util.ErrTooShort
	}

	n := new(ImplicitSha256DigestComponent)
	n.tlvType = tlv.ImplicitSha256DigestComponent
	n.value = make([]byte, len(value))
	copy(n.value, value)
	return n, nil
}

func (n *ImplicitSha256DigestComponent) String() string {
	return "sha256digest=" + hex.EncodeToString(n.value)
}

// DeepCopy creates a deep copy of the name component.
func (n *ImplicitSha256DigestComponent) DeepCopy() NameComponent {
	return &ImplicitSha256DigestComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// SetValue sets the value of an ImplicitSha256DigestComponent.
func (n *ImplicitSha256DigestComponent) SetValue(value []byte) error {
	if len(value) != 32 {
		return util.ErrOutOfRange
	}
	n.value = make([]byte, 32)
	copy(n.value, value)
	return nil
}

//////////////////////////////////
// ParametersSha256DigestComponent
//////////////////////////////////

// ParametersSha256DigestComponent represents a component containing the SHA-256 digest of the Interest parameters.
type ParametersSha256DigestComponent struct {
	BaseNameComponent
}

// NewParametersSha256DigestComponent creates a new ParametersSha256DigestComponent.
func NewParametersSha256DigestComponent(value []byte) (*ParametersSha256DigestComponent, error) {
	if len(value) != 32 {
		return nil, util.ErrTooShort
	}

	n := new(ParametersSha256DigestComponent)
	n.tlvType = tlv.ParametersSha256DigestComponent
	n.value = make([]byte, len(value))
	copy(n.value, value)
	return n, nil
}

func (n *ParametersSha256DigestComponent) String() string {
	return "params-sha256=" + hex.EncodeToString(n.value)
}

// DeepCopy creates a deep copy of the name component.
func (n *ParametersSha256DigestComponent) DeepCopy() NameComponent {
	return &ParametersSha256DigestComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// SetValue sets the value of an ParametersSha256DigestComponent.
func (n *ParametersSha256DigestComponent) SetValue(value []byte) error {
	if len(value) != 32 {
		return util.ErrOutOfRange
	}
	n.value = make([]byte, 32)
	copy(n.value, value)
	return nil
}

///////////////////////
// GenericNameComponent
///////////////////////

// GenericNameComponent represents a generic NDN name component.
type GenericNameComponent struct {
	BaseNameComponent
}

// NewGenericNameComponent creates a new GenericNameComponent.
func NewGenericNameComponent(value []byte) (*GenericNameComponent, error) {
	if len(value) == 0 {
		return nil, util.ErrTooShort
	}

	n := new(GenericNameComponent)
	n.tlvType = tlv.GenericNameComponent
	n.value = make([]byte, len(value))
	copy(n.value, value)
	return n, nil
}

func (n *GenericNameComponent) String() string {
	return string(n.value)
}

// DeepCopy creates a deep copy of the name component.
func (n *GenericNameComponent) DeepCopy() NameComponent {
	return &GenericNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// SetValue sets the value of a GenericNameComponent.
func (n *GenericNameComponent) SetValue(value []byte) {
	n.value = make([]byte, len(value))
	copy(n.value, value)
}

///////////////////////
// KeywordNameComponent
///////////////////////

// KeywordNameComponent is a component containing a well-known keyword.
type KeywordNameComponent struct {
	BaseNameComponent
}

// NewKeywordNameComponent creates a new KeywordNameComponent.
func NewKeywordNameComponent(value []byte) (*KeywordNameComponent, error) {
	if len(value) == 0 {
		return nil, util.ErrTooShort
	}

	n := new(KeywordNameComponent)
	n.tlvType = tlv.KeywordNameComponent
	n.value = make([]byte, len(value))
	copy(n.value, value)
	return n, nil
}

func (n *KeywordNameComponent) String() string {
	return string(n.value)
}

// DeepCopy creates a deep copy of the name component.
func (n *KeywordNameComponent) DeepCopy() NameComponent {
	return &KeywordNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// SetValue sets the value of a KeywordNameComponent.
func (n *KeywordNameComponent) SetValue(value []byte) {
	n.value = make([]byte, len(value))
	copy(n.value, value)
}

///////////////////////
// SegmentNameComponent
///////////////////////

// SegmentNameComponent is a component containing a segment number.
type SegmentNameComponent struct {
	BaseNameComponent
}

// NewSegmentNameComponent creates a new SegmentNameComponent.
func NewSegmentNameComponent(value uint64) (*SegmentNameComponent, error) {
	n := new(SegmentNameComponent)
	n.tlvType = tlv.SegmentNameComponent
	n.value = make([]byte, 8)
	binary.BigEndian.PutUint64(n.value, value)
	return n, nil
}

func (n *SegmentNameComponent) String() string {
	return "seg=" + strconv.FormatUint(binary.BigEndian.Uint64(n.value), 10)
}

// DeepCopy creates a deep copy of the name component.
func (n *SegmentNameComponent) DeepCopy() NameComponent {
	return &SegmentNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// Encode encodes a SegmentNameComponent.
func (n *SegmentNameComponent) Encode() *tlv.Block {
	return tlv.EncodeNNIBlock(uint32(n.tlvType), binary.BigEndian.Uint64(n.value))
}

// SetValue sets the value of a KeywordNameComponent.
func (n *SegmentNameComponent) SetValue(value uint64) {
	binary.BigEndian.PutUint64(n.value, value)
}

//////////////////////////
// ByteOffsetNameComponent
//////////////////////////

// ByteOffsetNameComponent is a component containing a byte offset.
type ByteOffsetNameComponent struct {
	BaseNameComponent
}

// NewByteOffsetNameComponent creates a new ByteOffsetNameComponent.
func NewByteOffsetNameComponent(value uint64) (*ByteOffsetNameComponent, error) {
	n := new(ByteOffsetNameComponent)
	n.tlvType = tlv.ByteOffsetNameComponent
	n.value = make([]byte, 8)
	binary.BigEndian.PutUint64(n.value, value)
	return n, nil
}

func (n *ByteOffsetNameComponent) String() string {
	return "off=" + strconv.FormatUint(binary.BigEndian.Uint64(n.value), 10)
}

// DeepCopy creates a deep copy of the name component.
func (n *ByteOffsetNameComponent) DeepCopy() NameComponent {
	return &ByteOffsetNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// Encode encodes a ByteOffsetNameComponent.
func (n *ByteOffsetNameComponent) Encode() *tlv.Block {
	return tlv.EncodeNNIBlock(uint32(n.tlvType), binary.BigEndian.Uint64(n.value))
}

// SetValue sets the value of a ByteOffsetNameComponent.
func (n *ByteOffsetNameComponent) SetValue(value uint64) {
	binary.BigEndian.PutUint64(n.value, value)
}

///////////////////////
// VersionNameComponent
///////////////////////

// VersionNameComponent is a component containing a version number.
type VersionNameComponent struct {
	BaseNameComponent
}

// NewVersionNameComponent creates a new VersionNameComponent.
func NewVersionNameComponent(value uint64) (*VersionNameComponent, error) {
	n := new(VersionNameComponent)
	n.tlvType = tlv.VersionNameComponent
	n.value = make([]byte, 8)
	binary.BigEndian.PutUint64(n.value, value)
	return n, nil
}

func (n *VersionNameComponent) String() string {
	return "v=" + strconv.FormatUint(binary.BigEndian.Uint64(n.value), 10)
}

// DeepCopy creates a deep copy of the name component.
func (n *VersionNameComponent) DeepCopy() NameComponent {
	return &VersionNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// Encode encodes a VersionNameComponent.
func (n *VersionNameComponent) Encode() *tlv.Block {
	return tlv.EncodeNNIBlock(uint32(n.tlvType), binary.BigEndian.Uint64(n.value))
}

// SetValue sets the value of a VersionNameComponent.
func (n *VersionNameComponent) SetValue(value uint64) {
	binary.BigEndian.PutUint64(n.value, value)
}

/////////////////////////
// TimestampNameComponent
/////////////////////////

// TimestampNameComponent is a component containing a Unix timestamp (in microseconds).
type TimestampNameComponent struct {
	BaseNameComponent
}

// NewTimestampNameComponent creates a new TimestampNameComponent.
func NewTimestampNameComponent(value uint64) (*TimestampNameComponent, error) {
	n := new(TimestampNameComponent)
	n.tlvType = tlv.TimestampNameComponent
	n.value = make([]byte, 8)
	binary.BigEndian.PutUint64(n.value, value)
	return n, nil
}

func (n *TimestampNameComponent) String() string {
	return "t=" + strconv.FormatUint(binary.BigEndian.Uint64(n.value), 10)
}

// DeepCopy creates a deep copy of the name component.
func (n *TimestampNameComponent) DeepCopy() NameComponent {
	return &TimestampNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// Encode encodes a TimestampNameComponent.
func (n *TimestampNameComponent) Encode() *tlv.Block {
	return tlv.EncodeNNIBlock(uint32(n.tlvType), binary.BigEndian.Uint64(n.value))
}

// SetValue sets the value of a TimestampNameComponent.
func (n *TimestampNameComponent) SetValue(value uint64) {
	binary.BigEndian.PutUint64(n.value, value)
}

///////////////////////////
// SequenceNumNameComponent
///////////////////////////

// SequenceNumNameComponent is a component containing a sequence number.
type SequenceNumNameComponent struct {
	BaseNameComponent
}

// NewSequenceNumNameComponent creates a new SequenceNumNameComponent.
func NewSequenceNumNameComponent(value uint64) (*SequenceNumNameComponent, error) {
	n := new(SequenceNumNameComponent)
	n.tlvType = tlv.SequenceNumNameComponent
	n.value = make([]byte, 8)
	binary.BigEndian.PutUint64(n.value, value)
	return n, nil
}

func (n *SequenceNumNameComponent) String() string {
	return "seq=" + strconv.FormatUint(binary.BigEndian.Uint64(n.value), 10)
}

// DeepCopy creates a deep copy of the name component.
func (n *SequenceNumNameComponent) DeepCopy() NameComponent {
	return &SequenceNumNameComponent{BaseNameComponent: *n.BaseNameComponent.DeepCopy().(*BaseNameComponent)}
}

// Encode encodes a SequenceNumNameComponent.
func (n *SequenceNumNameComponent) Encode() *tlv.Block {
	return tlv.EncodeNNIBlock(uint32(n.tlvType), binary.BigEndian.Uint64(n.value))
}

// SetValue sets the value of a SequenceNumNameComponent.
func (n *SequenceNumNameComponent) SetValue(value uint64) {
	binary.BigEndian.PutUint64(n.value, value)
}

///////
// Name
///////

// Name represents an NDN name.
type Name struct {
	components []NameComponent
	wire       tlv.Block
}

// NewName constructs an empty name.
func NewName() *Name {
	n := new(Name)
	return n
}

// DecodeName decodes a name from wire encoding.,
func DecodeName(b *tlv.Block) (*Name, error) {
	if b == nil {
		return nil, util.ErrNonExistent
	}
	_, err := b.Wire()
	if err != nil {
		return nil, err
	}
	if b.Type() != tlv.Name {
		return nil, tlv.ErrUnrecognized
	}

	n := new(Name)
	b.Parse()
	for _, elem := range b.Subelements() {
		component, err := DecodeNameComponent(elem)
		if err != nil {
			return nil, err
		}
		n.Append(component)
	}
	n.wire = *b.DeepCopy()
	n.wire.Wire()
	return n, nil
}

func (n *Name) String() string {
	if n.Size() == 0 {
		return "/"
	}

	var out string
	for _, component := range n.components {
		out += "/" + component.String()
	}
	return out
}

// Append adds the specified name component to the end of the name.
func (n *Name) Append(component NameComponent) error {
	if component == nil {
		return util.ErrNonExistent
	}
	//n.components = append(n.components, reflect.New(reflect.ValueOf(component).Elem().Type()).Interface().(NameComponent))
	n.components = append(n.components, component.DeepCopy())
	n.wire.Reset()
	return nil
}

// At returns the name component at the specified index. If out of range, nil is returned.
func (n *Name) At(index int) NameComponent {
	if index < 0 || index >= len(n.components) {
		return nil
	}
	return n.components[index]
}

// Clear erases all components from the name.
func (n *Name) Clear() {
	if len(n.components) > 0 {
		n.components = make([]NameComponent, 0)
		n.wire.Reset()
	}
}

// DeepCopy makes a deep copy of the name component.
func (n *Name) DeepCopy() *Name {
	newN := new(Name)
	newN.components = make([]NameComponent, 0, len(n.components))
	for _, component := range n.components {
		newN.components = append(newN.components, component.DeepCopy())
	}
	return newN
}

// Equals returns whether the specified name is equal to this name.
func (n *Name) Equals(other *Name) bool {
	if n.Size() != other.Size() {
		return false
	}

	for i := 0; i < n.Size(); i++ {
		if n.At(i).Type() != other.At(i).Type() || !bytes.Equal(n.At(i).Value(), other.At(i).Value()) {
			return false
		}
	}

	return true
}

// Erase erases the specified name component. If out of range, no action is taken.
func (n *Name) Erase(index int) {
	if index < 0 || index >= len(n.components) {
		return
	}

	copy(n.components[index:], n.components[index+1:])
	n.components = n.components[:len(n.components)-1]
	n.wire.Reset()
}

// HasWire returns whether the name has a wire encoding.
func (n *Name) HasWire() bool {
	return n.wire.HasWire()
}

// Prefix returns a name prefix of the specified number of components. If greater than or equal to the size of the name, this returns a copy of the name.
func (n *Name) Prefix(size int) *Name {
	prefix := *n
	// We have to deep copy this
	prefix.components = make([]NameComponent, 0, len(n.components))
	for i := 0; i < size; i++ {
		//prefix.components = append(prefix.components, reflect.New(reflect.ValueOf(component).Elem().Type()).Interface().(NameComponent))
		prefix.components = append(prefix.components, n.components[i].DeepCopy())
	}
	// Reset wire
	prefix.wire = tlv.Block{}
	return &prefix
}

// PrefixOf returns whether this name is a prefix of the specified name.
func (n *Name) PrefixOf(other *Name) bool {
	if other == nil || n.Size() > other.Size() {
		return false
	}

	for i := 0; i < n.Size(); i++ {
		if n.At(i).Type() != other.At(i).Type() || !bytes.Equal(n.At(i).Value(), other.At(i).Value()) {
			return false
		}
	}

	return true
}

// Set replaces the component at the specified index with the specified component.
func (n *Name) Set(index int, component NameComponent) error {
	if index < 0 || index >= len(n.components) {
		return util.ErrOutOfRange
	}

	//n.components[index] = reflect.New(reflect.ValueOf(component).Elem().Type()).Interface().(NameComponent)
	n.components[index] = component.DeepCopy()
	n.wire.Reset()
	return nil
}

// Size returns the number of components in the name.
func (n *Name) Size() int {
	return len(n.components)
}

// Wire returns the wire encoding of the name.
func (n *Name) Wire() *tlv.Block {
	if !n.wire.HasWire() {
		n.wire.Reset()
		n.wire.SetType(tlv.Name)

		for _, component := range n.components {
			n.wire.Append(component.Wire())
		}

		n.wire.Wire()
	}
	return n.wire.DeepCopy()
}
