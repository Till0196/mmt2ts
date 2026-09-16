// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package escan

// bits は RBSP を1ビットずつ読む。
//
// 末尾を越えた読み出しは0を返す。
// 途中で切れたストリームを特別扱いすると、呼ぶ側の一箇所ごとに長さの確認が要るためこうしてある。
type bits struct {
	buf []byte
	pos int
}

func (b *bits) u(n int) uint {
	var v uint
	for i := 0; i < n; i++ {
		v <<= 1
		if b.pos>>3 < len(b.buf) {
			v |= uint(b.buf[b.pos>>3]>>(7-uint(b.pos&7))) & 1
		}
		b.pos++
	}
	return v
}

func (b *bits) flag() bool { return b.u(1) == 1 }

// ue は Exp-Golomb の符号なし値を読む。
func (b *bits) ue() uint {
	zeros := 0
	for b.pos>>3 < len(b.buf) && b.u(1) == 0 {
		zeros++
		if zeros > 32 {
			return 0
		}
	}
	if zeros == 0 {
		return 0
	}
	return 1<<uint(zeros) - 1 + b.u(zeros)
}

func (b *bits) se() int {
	k := b.ue()
	if k%2 == 0 {
		return -int(k / 2)
	}
	return int(k/2) + 1
}

// rbsp は開始符号の偽装を防ぐために符号化器が挿入したバイトを取り除く。
func rbsp(nal []byte) []byte {
	out := make([]byte, 0, len(nal))
	for i := 0; i < len(nal); i++ {
		if i+2 < len(nal) && nal[i] == 0 && nal[i+1] == 0 && nal[i+2] == 3 {
			out = append(out, 0, 0)
			i += 2
			continue
		}
		out = append(out, nal[i])
	}
	return out
}

// gcd は縦横比や框率を約分するために使う。
func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

// ratio は約分した比を返す。分母が0なら申告が無かったものとして 0/1 にする。
func ratio(num, den int) (int, int) {
	if num <= 0 || den <= 0 {
		return 0, 1
	}
	g := gcd(num, den)
	if g == 0 {
		return 0, 1
	}
	return num / g, den / g
}
