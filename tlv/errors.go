/* GoNDN2 - NDN Forwarder Library for Go
 *
 * Copyright (C) 2020 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package tlv

import "errors"

// TLV errors
var (
	ErrBufferTooShort = errors.New("TLV length exceeds buffer size")
	ErrMissingLength  = errors.New("Missing TLV length")
	ErrOutOfRange     = errors.New("Value outside of allowed range")
	ErrTooLong        = errors.New("Value too long")
	ErrTooShort       = errors.New("Value too short")
	ErrUnrecognized   = errors.New("Unrecognized TLV type")
)
