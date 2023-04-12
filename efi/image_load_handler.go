// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package efi

import (
	"errors"
)

// imageLoadHandler is an abstraction for measuring boot events
// associated with a single image.
type imageLoadHandler interface {
	// MeasureImageStart measures events related to the execution
	// of the image associated with this handler to the supplied branch.
	MeasureImageStart(ctx pcrBranchContext) error

	// MeasureLoadEvent measures events related to the verification
	// and loading of the supplied image by the image associated with
	// this handler, to the supplied branch.
	MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error)
}

// imageLoadHandlers is an abstraction for mapping an image to an
// imageLoadHandler.
type imageLoadHandlers interface {
	// NewOrExisting returns an imageLoadHandler for the supplied image.
	NewOrExisting(image peImageHandle) (imageLoadHandler, error)
}

// newOrExistingImageLoadHandler returns an imageLoadHandler for the supplied image.
func newOrExistingImageLoadHandler(pc pcrProfileContext, image peImageHandle) (imageLoadHandler, error) {
	return pc.ImageLoadHandlers().NewOrExisting(image)
}

type nullLoadHandler struct{}

func newNullLoadHandler(_ secureBootAuthoritySet, _ peImageHandle) (imageLoadHandler, error) {
	return new(nullLoadHandler), nil
}

func (*nullLoadHandler) MeasureImageStart(_ pcrBranchContext) error {
	return nil
}

func (*nullLoadHandler) MeasureImageLoad(_ pcrBranchContext, _ peImageHandle) (imageLoadHandler, error) {
	return nil, errors.New("unrecognized image")
}
