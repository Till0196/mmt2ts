// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package timeline はNTPとMPU時刻をPTS、DTS、PCRの時間軸へ写す。
package timeline

const (
	Hz       = 90000
	SystemHz = 27000000
)

func NTPTo90k(base, t uint64) int64 {
	delta := int64(t - base)
	seconds := delta >> 32
	fraction := uint32(delta)
	return seconds*Hz + int64(uint64(fraction)*Hz>>32)
}

func NTPDeltaSeconds(a, b uint64) float64 {
	delta := int64(a - b)
	return float64(delta>>32) + float64(uint32(delta))/(1<<32)
}

func TicksTo90k(ticks int64, timescale uint32) int64 {
	if timescale == 0 {
		return 0
	}
	ts := int64(timescale)
	if ticks < 0 {
		return -((-ticks*Hz + ts/2) / ts)
	}
	return (ticks*Hz + ts/2) / ts
}

func To27MHz(ticks90k int64) int64 { return ticks90k * 300 }

type Base struct {
	ntp uint64
	set bool
}

func (b *Base) Set(ntp uint64) {
	if !b.set {
		b.ntp, b.set = ntp, true
	}
}

func (b *Base) IsSet() bool { return b.set }
func (b *Base) NTP() uint64 { return b.ntp }
func (b *Base) To90k(ntp uint64) int64 {
	return NTPTo90k(b.ntp, ntp)
}

const ntpEpochOffset = 2208988800

func UnixToNTP(unix int64) uint64 { return uint64(unix+ntpEpochOffset) << 32 }

func MJDBCDToUnix(v [5]byte) (int64, bool) {
	mjd := int64(v[0])<<8 | int64(v[1])
	if mjd == 0xffff {
		return 0, false
	}
	hour, ok1 := bcd(v[2])
	minute, ok2 := bcd(v[3])
	second, ok3 := bcd(v[4])
	if !ok1 || !ok2 || !ok3 || hour > 23 || minute > 59 || second > 60 {
		return 0, false
	}
	days := mjd - 40587
	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second) - 9*3600, true
}

func bcd(b byte) (int, bool) {
	hi, lo := int(b>>4), int(b&0x0f)
	if hi > 9 || lo > 9 {
		return 0, false
	}
	return hi*10 + lo, true
}
