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
	"golang.org/x/xerrors"
)

type grubFlags int

const (
	grubChainloaderUsesShimProtocol grubFlags = 1 << iota
)

type grubLoadHandler struct {
	Flags grubFlags
}

func newGrubLoadHandler(_ secureBootAuthoritySet, _ peImageHandle) (imageLoadHandler, error) {
	return new(grubLoadHandler), nil
}

func newGrubLoadHandlerWithFlags(flags grubFlags) newImageLoadHandlerFn {
	return func(_ secureBootAuthoritySet, _ peImageHandle) (imageLoadHandler, error) {
		return &grubLoadHandler{Flags: flags}, nil
	}
}

func (h *grubLoadHandler) MeasureImageStart(_ pcrBranchContext) error {
	return nil
}

func (h *grubLoadHandler) MeasureImageLoad(ctx pcrBranchContext, image peImageHandle) (imageLoadHandler, error) {
	var err error
	if h.Flags&grubChainloaderUsesShimProtocol != 0 {
		m := newShimImageLoadMeasurer(ctx, image)
		err = m.measure()
	} else {
		m := newFwImageLoadMeasurer(ctx, image)
		err = m.measure()
	}
	if err != nil {
		return nil, xerrors.Errorf("cannot measure image: %w", err)
	}

	return newOrExistingImageLoadHandler(ctx, image)
}
