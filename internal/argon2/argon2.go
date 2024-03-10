// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package argon2

import (
	"errors"
	"math"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	// Dummy password for benchmarking (same value used by cryptsetup)
	benchmarkPassword = "foo"
	benchmarkKeyLen   = 32

	initialTargetDuration = 250 * time.Millisecond

	minTimeCost      = 4
	minMemoryCostKiB = 32 * 1024
	maxMemoryCostKiB = 4 * 1024 * 1024

	tolerance = 0.05
)

var (
	// Dummy salt for benchmarking (same value used by cryptsetup)
	benchmarkSalt = []byte("0123456789abcdefghijklmnopqrstuv")
)

type Mode string

const (
	DataIndependent Mode = "argon2i"
	Hybrid          Mode = "argon2id"
)

func (m Mode) keyFn() func([]byte, []byte, uint32, uint32, uint8, uint32) []byte {
	switch m {
	case DataIndependent:
		return argon2.Key
	case Hybrid:
		return argon2.IDKey
	default:
		panic("invalid mode")
	}
}

// BenchmarkParams defines the parameters for benchmarking the Argon2 algorithm
type BenchmarkParams struct {
	// MaxMemoryCostKiB sets the upper memory usage limit in KiB. The actual
	// upper limit is capped at 4GiB or half of the available memory.
	MaxMemoryCostKiB uint32

	// TargetDuration sets the target time for which the benchmark will
	// compute cost parameters.
	TargetDuration time.Duration

	// Threads is the number of parallel threads that will be used
	// for the key derivation. Set this to zero to derive it from
	// the number of CPUs. The upper limit is capped at 4.
	Threads uint8
}

// CostParams defines the cost parameters for key derivation using Argon2. It
// can either be generated by Benchmark or supplied with well known values.
type CostParams struct {
	// Time corresponds to the number of iterations of the algorithm
	// that the key derivation will use.
	Time uint32

	// MemoryKiB is the amount of memory in KiB that the key derivation
	// will use.
	MemoryKiB uint32

	// Threads is the number of parallel threads that will be used
	// for the key derivation.
	Threads uint8
}

type benchmarkContext struct {
	keyFn            KeyDurationFunc // callback for running an individual measurement
	maxMemoryCostKiB uint32          // maximum memory cost
	cost             CostParams      // current computed cost parameters
	duration         time.Duration   // last measured duration

	// timeCostIncreaseCount tracks the number of consecutive increases
	// in the time cost.
	timeCostIncreaseCount int
}

// timeExecution measures the amount of time it takes to execute the Argon2i key
// derivation with the current cost parameters. It will perform a number of
// measurements as specified by the iterations parameter and update the current
// duration with the minimum execution time. If any execution time is less than
// targetDuration, then it will return early without performing any further
// measurements.
func (c *benchmarkContext) timeExecution(iterations int, targetDuration time.Duration) error {
	var minDuration time.Duration

	for i := 0; i < iterations; i++ {
		duration, err := c.keyFn(&c.cost)
		if err != nil {
			return err
		}

		if i == 0 {
			minDuration = duration
		}
		if duration < minDuration {
			minDuration = duration
		}
		if minDuration < targetDuration {
			break
		}
	}

	c.duration = minDuration
	return nil
}

// isMakingProgress returns true if the number of consecutive increases in the time cost
// is less than 10. As there is no ceiling on the time cost, benchmarking should abort
// if this returns true, which might be an indication that the function used to time
// the algorithm is returning bogus numbers.
func (c *benchmarkContext) isMakingProgress() bool {
	return c.timeCostIncreaseCount < 10
}

// computeNextCostParameters calculates the next cost parameters to try based on the
// previous execution duration, target duration and current cost parameters.
func (c *benchmarkContext) computeNextCostParams(targetDuration time.Duration) (done bool) {
	newTimeCost := c.cost.Time
	newMemoryCostKiB := c.cost.MemoryKiB
	newTimeCostIncreaseCount := 0

	switch {
	case c.duration < targetDuration:
		// Previous duration was shorter than the target duration, so
		// we need to increase the cost.
		switch {
		case c.cost.MemoryKiB < c.maxMemoryCostKiB:
			// Current memory cost is less than the maximum, so increase the memory cost.
			newMemoryCostKiB = uint32((int64(c.cost.MemoryKiB) * int64(targetDuration)) / int64(c.duration))
			if newMemoryCostKiB > c.maxMemoryCostKiB {
				// New memory cost overshoots the maximum, so set it to the maximum
				// and increase the time cost by a proportionate amount.
				newMemoryCostKiB = c.maxMemoryCostKiB
				newTimeCost = uint32((int64(c.cost.Time*c.cost.MemoryKiB) * int64(targetDuration)) / (int64(c.duration) * int64(c.maxMemoryCostKiB)))
				newTimeCostIncreaseCount = c.timeCostIncreaseCount + 1
			}
		default:
			// Current memory cost is at the maximum, so increase the time cost.
			// There is no maximum time cost.
			newTimeCost = uint32((int64(c.cost.Time) * int64(targetDuration)) / int64(c.duration))
			newTimeCostIncreaseCount = c.timeCostIncreaseCount + 1
		}
	case c.duration > targetDuration:
		// Previous duration was longer than the target duration, so
		// we need to decrease the cost.
		switch {
		case c.cost.Time > minTimeCost:
			// Current time cost is greater than the minimum time cost, so
			// decrease the time cost.
			newTimeCost = uint32((int64(c.cost.Time) * int64(targetDuration)) / int64(c.duration))
			if newTimeCost < minTimeCost {
				// New time cost undershoots the minimum, so set it to the minimum
				// and decrease the memory cost by a proportionate amount.
				newTimeCost = minTimeCost
				newMemoryCostKiB = uint32((int64(c.cost.MemoryKiB*c.cost.Time) * int64(targetDuration)) / (int64(c.duration) * minTimeCost))
				if newMemoryCostKiB < minMemoryCostKiB {
					// New memory cost undershoots the minimum, so set it to the
					// minimum and end the benchmarking.
					newMemoryCostKiB = minMemoryCostKiB
					done = true
				}
			}
		default:
			// Current time cost is at the minimum, so decrease the memory cost.
			newMemoryCostKiB = uint32((int64(c.cost.MemoryKiB) * int64(targetDuration)) / int64(c.duration))
			if newMemoryCostKiB < minMemoryCostKiB {
				// New memory cost undershoots the minimum, so set it to the
				// minimum and end the benchmarking.
				newMemoryCostKiB = minMemoryCostKiB
				done = true
			}
		}
	}

	if c.cost.Time == newTimeCost && c.cost.MemoryKiB == newMemoryCostKiB {
		// The cost parameters are unchanged, so end the benchmarking.
		done = true
	}

	c.cost.Time = newTimeCost
	c.cost.MemoryKiB = newMemoryCostKiB
	c.timeCostIncreaseCount = newTimeCostIncreaseCount

	return done
}

func (c *benchmarkContext) run(params *BenchmarkParams, keyFn KeyDurationFunc, sysInfo *unix.Sysinfo_t, numCpu int) (*CostParams, error) {
	c.keyFn = keyFn

	// Set a ceiling on the maximum memory cost of half of the
	// available RAM or 4GB, whichever is less.
	halfTotalRamKiB := uint64(sysInfo.Totalram) * uint64(sysInfo.Unit) / 2048
	if halfTotalRamKiB > math.MaxUint32 {
		halfTotalRamKiB = math.MaxUint32
	}

	c.maxMemoryCostKiB = uint32(maxMemoryCostKiB)
	if uint32(halfTotalRamKiB) < c.maxMemoryCostKiB {
		c.maxMemoryCostKiB = uint32(halfTotalRamKiB)
	}
	if params.MaxMemoryCostKiB < c.maxMemoryCostKiB {
		c.maxMemoryCostKiB = params.MaxMemoryCostKiB
	}

	// Set the number of threads to the number of CPUs or use
	// the number supplied (maximum 4)
	threads := numCpu
	if params.Threads > 0 {
		threads = int(params.Threads)
	}
	if threads > 4 {
		threads = 4
	}
	c.cost.Threads = uint8(threads)

	// Set the time and memory cost to their minimum values.
	c.cost.Time = minTimeCost
	c.cost.MemoryKiB = minMemoryCostKiB

	// Perform an initial benchmark with a target duration of 250ms
	for i := 0; c.duration < initialTargetDuration; i++ {
		if i > 0 {
			if c.duration < 25*time.Millisecond {
				c.duration = 25 * time.Millisecond
			}
			if done := c.computeNextCostParams(initialTargetDuration); done {
				break
			}
		}

		if !c.isMakingProgress() {
			return nil, errors.New("not making sufficient progress")
		}
		if err := c.timeExecution(3, initialTargetDuration); err != nil {
			return nil, err
		}
	}

	// Starting with the parameters from the initial benchmark, perform the
	// proper benchmark with the supplied target duration and a +/-5% tolerance.
	minTargetDuration := params.TargetDuration - time.Duration(float64(params.TargetDuration)*tolerance)
	maxTargetDuration := params.TargetDuration + time.Duration(float64(params.TargetDuration)*tolerance)
	for c.duration < minTargetDuration || c.duration > maxTargetDuration {
		if done := c.computeNextCostParams(params.TargetDuration); done {
			break
		}

		if !c.isMakingProgress() {
			return nil, errors.New("not making sufficient progress")
		}
		if err := c.timeExecution(1, params.TargetDuration); err != nil {
			return nil, err
		}
	}

	return &c.cost, nil
}

// KeyDuration runs the key derivation with the built-in benchmarking values for the
// specified mode and supplied set of cost parameters, and then returns the amount of
// time taken to execute.
//
// By design, this function consumes a lot of memory depending on the supplied
// parameters. It may be desirable to execute it in a short-lived utility process.
func KeyDuration(mode Mode, params *CostParams) time.Duration {
	start := time.Now()
	Key(benchmarkPassword, benchmarkSalt, mode, params, benchmarkKeyLen)
	return time.Now().Sub(start)
}

// KeyDurationFunc provides a mechanism to delegate key derivation measurements
// to a short-lived utility process during benchmarking.
type KeyDurationFunc func(params *CostParams) (time.Duration, error)

// Benchmark computes the cost parameters for the desired duration and maximum
// memory cost.
//
// The algorithm is based on the one implemented in cryptsetup. If the current
// duration is shorter than the target duration, then increasing the memory cost
// is prioritized over increasing the time cost. The time cost is only increased
// once the maximum memory cost has been reached. If the current duration is
// longer than the target duration, then decreasing the time cost is prioritized
// over decreasing the memory cost. The memory cost is only decreased once the
// hard-coded minimum time cost has been reached.
//
// The package hard codes a minimum time cost of 4 iterations, and a minimum
// memory cost of 32MiB. A maximum memory cost of half of the total RAM or 4GB
// provides a ceiling to the supplied maximum memory cost. The algorithm will
// set 1 thread per CPU, up to a limit of 4 threads.
//
// The supplied callback is used to actually run the key derivation measurement,
// which will consume a lot of memory depending on the supplied parameters. Each
// measurement should generally be delegated to a short-lived utility process,
// which should call the KeyDuration function from this package. If the measurement
// is performed in the current process, the garbage collector must be executed at
// the end of each measurement.
func Benchmark(params *BenchmarkParams, keyFn KeyDurationFunc) (*CostParams, error) {
	var sysInfo unix.Sysinfo_t
	if err := unixSysinfo(&sysInfo); err != nil {
		return nil, xerrors.Errorf("cannot determine available memory: %w", err)
	}

	context := new(benchmarkContext)
	return context.run(params, keyFn, &sysInfo, runtimeNumCPU())
}

// Key derives a key of the desired length from the supplied passphrase and salt using the
// specified mode with the supplied cost parameters.
//
// By design, this function consumes a lot of memory depending on the supplied parameters.
// It may be desirable to execute it in a short-lived utility process.
//
// This will panic if the time or threads cost parameter are zero.
func Key(passphrase string, salt []byte, mode Mode, params *CostParams, keyLen uint32) []byte {
	return mode.keyFn()([]byte(passphrase), salt, params.Time, params.MemoryKiB, params.Threads, keyLen)
}
