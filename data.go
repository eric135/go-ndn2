/* GoNDN2 - NDN Forwarder Library for Go
 *
 * Copyright (C) 2020 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package ndn

import "github.com/eric135/go-ndn2/tlv"

// Data represents an NDN Data packet.
type Data struct {
	// TODO
}

// DecodeData decodes a Data packet from the wire.
func DecodeData(wire *tlv.Block) *Data {
	// TODO
	return nil
}

// DeepCopy returns a deep copy of the Data.
func (d *Data) DeepCopy() *Data {
	// TODO
	return nil
}

// Encode encodes the Data into a block.
func (d *Data) Encode() *tlv.Block {
	// TODO
	return nil
}
