/*
Copyright (c) 2012 Jens Zeilund (http://sketchground.dk)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// Sequence Key:
// 66F24B34AE4D26DADA87ABF799B247AABE389D5E02E08622D9E0F70C6A44E061

// Character Set:
// !#%+23456789:=?@ABCDEFGHJKLMNPRS
// TUVWXYZabcdefghijkmnopqrstuvwxyz

// Passcode length:
// 4

// First Passcard to generate:
// 1

// PPP Passcard Demo                  [1]
//     A    B    C    D    E    F    G
//  1: AWmL izmn ?eb: zNvm AX9R us+2 F?#F
//  2: JCDV cLkM V%zY 9PHF 5?xt +mK! MyDT
//  3: DE!G 4Ftj Zywg 6Nxd buGf :AP8 ub?n
//  4: snTq WRyD ytCc @7YE 5eHX !9ps ChpS
//  5: SeC+ uy2N =Pzk jS6d ?zat +Em2 5qsz
//  6: cjX+ YuRo Smr2 CBLq UKxp UEZ4 #x8i
//  7: 3G#7 Vv7j ?cJ6 db9r i8MB b6Bd G65n
//  8: u%62 8LrP F6:A #wPg hYK! MhSf #SCr
//  9: fVUF MSNy 3k%5 6eT8 +kdJ vMx9 8c@X
// 10: !JvY @v6g Sy27 5tFh nSxN PXYz 9%5A

// PPP Passcard Demo                  [2]
//     A    B    C    D    E    F    G
//  1: 4wED Rv+L 4FAf KB8C VZq2 rYxw +93T
//  2: qk5x F5Ew Rg9h j#TK r?5v ZRPN WFAz
//  3: @5!S qpDc NLEG rWZo yV=y KRoD rr5D
//  4: bqmz Cc?s 3FhR dpr@ 99Ld WZ+X 7?:d
//  5: Gzd2 mVjv PnCZ =S5W %MMY yi2j 6rjt
//  6: 9+gL GwWv P7ep qu9j ubAw #sAp 9tYL
//  7: xV!r PC6e dq5S zE?A 9du7 9ayw pzq2
//  8: t@Aw MXck 8HLj XfpB 3t3R bHU2 #g29
//  9: jY=X G8Ez 5qGA ohsC dqxA Gd8C rYv6
// 10: irVe 2zr6 vn!R FF@Y g2Tn @RpP S+bU

// PPP Passcard Demo                  [3]
//     A    B    C    D    E    F    G
//  1: JEiE =W:w iX=j b6kS #md5 @5aa =K%Z
//  2: NkYT KLcA 8FSM X6Jn cqvi 4?s# nATF
//  3: vhcm JizR +joS 8=Zn oZ9d +o6S 93Ht
//  4: =yfi u2dc ZASY f9Ro P:uR 9V!? 3No9
//  5: TLvS 4kXX MDrp T+A7 hZoC fCcT RWgm
//  6: HK?k 7wsw U@fY rvJo bE3N t8JW ioSk
//  7: ZBbj DKhe 4S=Y X@#q =LuK 3C3g R+S7
//  8: CN4: umAr aG5j 3z:X kAEH FPKY L!qt
//  9: fxn2 fWgk AENU zJTq jowD oEZP @wpV
// 10: B=at !fev bgGW oH#A gNVd K8XU 2U=o
package ppp

import (
	"math/big"
	"testing"
	"encoding/hex"
	"bytes"
)

func TestGetPasscode(t *testing.T) {
	sequencekey, err := ConvertHexToKey("66F24B34AE4D26DADA87ABF799B247AABE389D5E02E08622D9E0F70C6A44E061")
	if err != nil {
		t.Error("Could not convert Hex value to key")
	}
	alphabet := "!#%+23456789:=?@ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	bigint := big.NewInt(0)
	ppp := NewPpp(sequencekey, alphabet, 4, 20)
	passcode := ppp.GetPasscode(bigint)
	if passcode != "AWmL" {
		t.Error("Passcode is different from AWmL")
	}
	bigint = bigint.SetInt64(20)
	passcode = ppp.GetPasscode(bigint)
	if passcode != "ub?n" {
		t.Error("Passcode is different from ub?n")
	}
}

func TestGenerateSequenceKeyFromString(t *testing.T) {
	sequenceKey := GenerateSequenceKeyFromString("bob")
	h, _ := hex.DecodeString("81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9")
	if bytes.Compare(sequenceKey, h) != 0 {
		t.Error("Generated sequenceKey doesn't match")
	}
	h, _ = hex.DecodeString("77af778b51abd4a3c51c5ddd97204a9c3ae614ebccb75a606c3b6865aed6744e")
	sequenceKeyT := GenerateSequenceKeyFromString("cat")
	if bytes.Compare(sequenceKeyT, h) != 0 {
		t.Error("Generated sequenceKey doesn't match")
	}
}
