package implementation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/vm/embedded/definition"
)

type msgRow struct {
	ChainIdentifier uint64 `json:"chainIdentifier"`
	PointType       uint8  `json:"pointType"`
	Id              string `json:"id"`
	Destination     string `json:"destination"`
	Message         string `json:"message"`
}

type lockRow struct {
	PointType uint8  `json:"pointType"`
	PointLock string `json:"pointLock"`
	Error     string `json:"error"`
	Note      string `json:"note"`
}

type createRow struct {
	PointType   uint8  `json:"pointType"`
	PointLock   string `json:"pointLock"`
	Destination string `json:"destination"`
	Error       string `json:"error"`
	Note        string `json:"note"`
}

type witnessRow struct {
	PointType       uint8  `json:"pointType"`
	PointLock       string `json:"pointLock"`
	ChainIdentifier uint64 `json:"chainIdentifier"`
	Id              string `json:"id"`
	Destination     string `json:"destination"`
	Witness         string `json:"witness"`
	Error           string `json:"error"`
	Note            string `json:"note"`
}

type termsRow struct {
	TimeLocked     string `json:"timeLocked"`
	Destination    string `json:"destination"`
	TokenStandard  string `json:"tokenStandard"`
	Amount         string `json:"amount"`
	ExpirationTime int64  `json:"expirationTime"`
	PointType      uint8  `json:"pointType"`
	PointLock      string `json:"pointLock"`
}

type reclaimMsgRow struct {
	ChainIdentifier  uint64   `json:"chainIdentifier"`
	ReclaimPointType uint8    `json:"reclaimPointType"`
	Terms            termsRow `json:"terms"`
	Message          string   `json:"message"`
}

type createReclaimRow struct {
	PointType        uint8  `json:"pointType"`
	PointLock        string `json:"pointLock"`
	Destination      string `json:"destination"`
	ReclaimPointType uint8  `json:"reclaimPointType"`
	ReclaimPointLock string `json:"reclaimPointLock"`
	Error            string `json:"error"`
	Note             string `json:"note"`
}

type reclaimSigRow struct {
	ChainIdentifier  uint64   `json:"chainIdentifier"`
	Terms            termsRow `json:"terms"`
	ReclaimPointType uint8    `json:"reclaimPointType"`
	ReclaimPointLock string   `json:"reclaimPointLock"`
	Signature        string   `json:"signature"`
	Error            string   `json:"error"`
	Note             string   `json:"note"`
}

type vectors struct {
	Source                string             `json:"source"`
	UnlockMessage         []msgRow           `json:"unlockMessage"`
	PointLock             []lockRow          `json:"pointLock"`
	Create                []createRow        `json:"create"`
	Witness               []witnessRow       `json:"witness"`
	Abi                   []abiRow           `json:"abi"`
	Info                  []string           `json:"info"`
	ReclaimMessage        []reclaimMsgRow    `json:"reclaimMessage"`
	ReclaimLock           []lockRow          `json:"reclaimLock"`
	CreateWithReclaimLock []createReclaimRow `json:"createWithReclaimLock"`
	ReclaimSignature      []reclaimSigRow    `json:"reclaimSignature"`
	ReclaimLockInfo       []string           `json:"reclaimLockInfo"`
}

func termsOf(e *definition.PtlcInfo) termsRow {
	return termsRow{e.TimeLocked.String(), e.Destination.String(), e.TokenStandard.String(), e.Amount.String(), e.ExpirationTime, e.PointType, h(e.PointLock)}
}

type abiRow struct {
	Method string        `json:"method"`
	Args   []interface{} `json:"args"`
	Data   string        `json:"data"`
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func h(b []byte) string { return hex.EncodeToString(b) }

func seed(tag string, i int) []byte {
	s := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
	t := sha256.Sum256(append([]byte(tag), s[:]...))
	return t[:]
}

func TestDumpPtlcVectors(t *testing.T) {
	out := os.Getenv("PTLC_VECTORS_OUT")
	if out == "" {
		t.Skip("PTLC_VECTORS_OUT not set")
	}
	v := vectors{Source: os.Getenv("PTLC_VECTORS_SOURCE")}

	user1 := types.PubKeyToAddress(ed25519.NewKeyFromSeed(seed("user", 1)).Public().(ed25519.PublicKey))
	user2 := types.PubKeyToAddress(ed25519.NewKeyFromSeed(seed("user", 2)).Public().(ed25519.PublicKey))
	contractTypeOffList := types.Address{}
	contractTypeOffList[0] = types.ContractAddrByte
	copy(contractTypeOffList[1:], seed("contract", 1)[:19])
	addresses := []types.Address{types.ZeroAddress, user1, user2, types.PtlcContract, types.HtlcContract, contractTypeOffList}

	var ids []types.Hash
	for i := 0; i < 3; i++ {
		ids = append(ids, types.BytesToHashPanic(seed("id", i)))
	}
	chains := []uint64{1, 3, 69, 321, 1<<32 + 7, 1<<63 - 1}
	for _, c := range chains {
		for pt := uint8(0); pt <= 3; pt++ {
			for i, id := range ids {
				for j, d := range addresses {
					if (i+j+int(pt))%2 == 1 && c != 69 {
						continue
					}
					v.UnlockMessage = append(v.UnlockMessage, msgRow{c, pt, id.String(), d.String(), h(definition.GetPtlcUnlockMessage(c, pt, id, d))})
				}
			}
		}
	}

	addLock := func(pt uint8, lock []byte, note string) {
		v.PointLock = append(v.PointLock, lockRow{pt, h(lock), errString(checkPointLock(pt, lock)), note})
	}

	smallOrder := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for _, s := range smallOrder {
		b, _ := hex.DecodeString(s)
		addLock(definition.PointTypeED25519, b, "small order")
	}
	var torsion []*edwards25519.Point
	for _, s := range smallOrder[:8] {
		b, _ := hex.DecodeString(s)
		p, err := new(edwards25519.Point).SetBytes(b)
		if err == nil {
			torsion = append(torsion, p)
		}
	}
	for i := 0; i < 8; i++ {
		pub := ed25519.NewKeyFromSeed(seed("ed", i)).Public().(ed25519.PublicKey)
		addLock(definition.PointTypeED25519, pub, "key")
		p, _ := new(edwards25519.Point).SetBytes(pub)
		mixed := new(edwards25519.Point).Add(p, torsion[(i%(len(torsion)-1))+1])
		addLock(definition.PointTypeED25519, mixed.Bytes(), "key plus torsion")
	}
	pField := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for k := int64(0); k < 19; k++ {
		y := new(big.Int).Add(pField, big.NewInt(k))
		le := make([]byte, 32)
		be := y.FillBytes(make([]byte, 32))
		for i := range be {
			le[i] = be[31-i]
		}
		addLock(definition.PointTypeED25519, le, "y at or above the field prime")
		le2 := append([]byte(nil), le...)
		le2[31] |= 0x80
		addLock(definition.PointTypeED25519, le2, "y at or above the field prime, sign set")
	}
	for k := byte(2); k < 40; k++ {
		b := make([]byte, 32)
		b[0] = k
		addLock(definition.PointTypeED25519, b, "small y")
		b2 := append([]byte(nil), b...)
		b2[31] = 0x80
		addLock(definition.PointTypeED25519, b2, "small y, sign set")
	}
	addLock(definition.PointTypeED25519, make([]byte, 31), "short")
	addLock(definition.PointTypeED25519, make([]byte, 33), "long")

	for i := 0; i < 8; i++ {
		priv, _ := btcec.PrivKeyFromBytes(seed("bip340", i))
		addLock(definition.PointTypeBIP340, schnorr.SerializePubKey(priv.PubKey()), "key")
		addLock(definition.PointTypeSecp256k1Point, priv.PubKey().SerializeCompressed(), "point")
		unc := priv.PubKey().SerializeUncompressed()
		bad := append([]byte{0x04}, unc[1:33]...)
		addLock(definition.PointTypeSecp256k1Point, bad, "prefix 04")
		bad = append([]byte{0x00}, unc[1:33]...)
		addLock(definition.PointTypeSecp256k1Point, bad, "prefix 00")
		bad = append([]byte{0x06 | (unc[64] & 1)}, unc[1:33]...)
		addLock(definition.PointTypeSecp256k1Point, bad, "hybrid prefix")
	}
	for k := byte(0); k < 24; k++ {
		x := make([]byte, 32)
		x[31] = k
		addLock(definition.PointTypeBIP340, x, "small x")
		addLock(definition.PointTypeSecp256k1Point, append([]byte{0x02}, x...), "small x, even")
		addLock(definition.PointTypeSecp256k1Point, append([]byte{0x03}, x...), "small x, odd")
	}
	pSecp, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	for k := int64(-2); k < 3; k++ {
		x := new(big.Int).Add(pSecp, big.NewInt(k)).FillBytes(make([]byte, 32))
		addLock(definition.PointTypeBIP340, x, "x near the field prime")
		addLock(definition.PointTypeSecp256k1Point, append([]byte{0x02}, x...), "x near the field prime")
	}
	ff := make([]byte, 32)
	for i := range ff {
		ff[i] = 0xff
	}
	addLock(definition.PointTypeBIP340, ff, "all ones")
	addLock(definition.PointTypeBIP340, make([]byte, 33), "long")
	addLock(definition.PointTypeSecp256k1Point, make([]byte, 32), "short")
	addLock(definition.PointTypeSecp256k1Point, make([]byte, 33), "zero")
	addLock(3, make([]byte, 32), "unknown point type")
	addLock(255, make([]byte, 33), "unknown point type")

	edPub := ed25519.NewKeyFromSeed(seed("ed", 0)).Public().(ed25519.PublicKey)
	bipPriv, _ := btcec.PrivKeyFromBytes(seed("bip340", 0))
	bipPub := schnorr.SerializePubKey(bipPriv.PubKey())
	ptPriv, _ := btcec.PrivKeyFromBytes(seed("scalar", 0))
	ptPub := ptPriv.PubKey().SerializeCompressed()
	smallOrderKey, _ := hex.DecodeString(smallOrder[0])
	for _, c := range []struct {
		pt   uint8
		lock []byte
	}{{0, edPub}, {1, bipPub}, {2, ptPub}, {0, smallOrderKey}, {3, edPub}} {
		for _, d := range addresses {
			p := definition.CreatePtlcParam{ExpirationTime: 1, PointType: c.pt, PointLock: c.lock, Destination: d}
			v.Create = append(v.Create, createRow{c.pt, h(c.lock), d.String(), errString(checkPtlc(p)), ""})
		}
	}

	addWitness := func(pt uint8, lock []byte, chain uint64, id types.Hash, d types.Address, w []byte, note string) {
		info := &definition.PtlcInfo{Id: id, PointType: pt, PointLock: lock}
		v.Witness = append(v.Witness, witnessRow{pt, h(lock), chain, id.String(), d.String(), h(w), errString(verifyPtlcWitness(info, chain, id, d, w)), note})
	}
	for i := 0; i < 6; i++ {
		id := ids[i%len(ids)]
		chain := chains[i%len(chains)]
		d := user1
		other := user2

		edKey := ed25519.NewKeyFromSeed(seed("ed", i))
		edLock := edKey.Public().(ed25519.PublicKey)
		msg := definition.GetPtlcUnlockMessage(chain, 0, id, d)
		sig := ed25519.Sign(edKey, msg)
		if i < 2 {
			addWitness(0, edLock, chain, id, d, sig, "valid")
		}
		if i < 2 {
			addWitness(0, edLock, chain, id, other, sig, "other destination")
		}
		if i < 2 {
			addWitness(0, edLock, chain^1, id, d, sig, "other chain")
		}
		if i < 2 {
			addWitness(0, edLock, chain, ids[(i+1)%len(ids)], d, sig, "other id")
		}
		bad := append([]byte(nil), sig...)
		bad[63] ^= 0x01
		if i < 2 {
			addWitness(0, edLock, chain, id, d, bad, "tampered")
		}
		if i < 2 {
			addWitness(0, edLock, chain, id, d, sig[:32], "short")
		}
		if i < 2 {
			addWitness(0, edLock, chain, id, d, ed25519.Sign(edKey, definition.GetPtlcUnlockMessage(chain, 1, id, d)), "signed for another point type")
		}

		bk, _ := btcec.PrivKeyFromBytes(seed("bip340", i))
		bLock := schnorr.SerializePubKey(bk.PubKey())
		bmsg := definition.GetPtlcUnlockMessage(chain, 1, id, d)
		bsig, err := schnorr.Sign(bk, bmsg)
		if err != nil {
			t.Fatal(err)
		}
		bs := bsig.Serialize()
		addWitness(1, bLock, chain, id, d, bs, "valid")
		addWitness(1, bLock, chain, id, other, bs, "other destination")
		addWitness(1, bLock, chain^1, id, d, bs, "other chain")
		bbad := append([]byte(nil), bs...)
		bbad[10] ^= 0x01
		addWitness(1, bLock, chain, id, d, bbad, "tampered")
		addWitness(1, bLock, chain, id, d, bs[:32], "short")
		bsig0, _ := schnorr.Sign(bk, definition.GetPtlcUnlockMessage(chain, 0, id, d))
		addWitness(1, bLock, chain, id, d, bsig0.Serialize(), "signed for another point type")

		sk, _ := btcec.PrivKeyFromBytes(seed("scalar", i))
		pLock := sk.PubKey().SerializeCompressed()
		scalar := sk.Key.Bytes()
		addWitness(2, pLock, chain, id, d, scalar[:], "valid")
		addWitness(2, pLock, chain, id, other, scalar[:], "destination is not part of the witness")
		other2, _ := btcec.PrivKeyFromBytes(seed("scalar", i+100))
		o := other2.Key.Bytes()
		addWitness(2, pLock, chain, id, d, o[:], "another scalar")
		var neg btcec.ModNScalar
		neg.Set(&sk.Key).Negate()
		nb := neg.Bytes()
		addWitness(2, pLock, chain, id, d, nb[:], "negated scalar")
		addWitness(2, pLock, chain, id, d, scalar[:31], "short")
		addWitness(2, pLock, chain, id, d, append(scalar[:], 0), "long")
	}
	nOrder := btcec.S256().N
	for k := int64(0); k < 3; k++ {
		sk, _ := btcec.PrivKeyFromBytes(seed("scalar", 0))
		pLock := sk.PubKey().SerializeCompressed()
		over := new(big.Int).Add(nOrder, new(big.Int).SetBytes(func() []byte { b := sk.Key.Bytes(); return b[:] }()))
		if over.BitLen() <= 256 && k == 0 {
			addWitness(2, pLock, 69, ids[0], user1, over.FillBytes(make([]byte, 32)), "scalar plus n")
		}
		addWitness(2, pLock, 69, ids[0], user1, new(big.Int).Add(nOrder, big.NewInt(k)).FillBytes(make([]byte, 32)), "n and above")
	}
	addWitness(2, ptPub, 69, ids[0], user1, make([]byte, 32), "zero scalar")
	one := make([]byte, 32)
	one[31] = 1
	g := make([]byte, 33)
	gb, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	copy(g, gb)
	addWitness(2, g, 69, ids[0], user1, one, "one opens the generator")
	addWitness(3, edPub, 69, ids[0], user1, make([]byte, 64), "unknown point type")

	pack := func(method string, args ...interface{}) string {
		b, err := definition.ABIPtlc.PackMethod(method, args...)
		if err != nil {
			t.Fatal(err)
		}
		return h(b)
	}
	sigs := [][]byte{seed("w", 0), append(seed("w", 1), seed("w", 2)...), {}, append(append(seed("w", 3), seed("w", 4)...), 7)}
	for i, l := range [][]byte{edPub, bipPub, ptPub} {
		for j, d := range []types.Address{types.ZeroAddress, user1} {
			exp := int64(1700000000 + i*1000 + j)
			v.Abi = append(v.Abi, abiRow{"Create", []interface{}{exp, i, h(l), d.String()}, pack("Create", exp, uint8(i), l, d)})
		}
	}
	for i, id := range ids {
		v.Abi = append(v.Abi, abiRow{"Reclaim", []interface{}{id.String()}, pack("Reclaim", id)})
		w := sigs[i%len(sigs)]
		v.Abi = append(v.Abi, abiRow{"Unlock", []interface{}{id.String(), h(w)}, pack("Unlock", id, w)})
		w2 := sigs[(i+1)%len(sigs)]
		v.Abi = append(v.Abi, abiRow{"ProxyUnlock", []interface{}{id.String(), user2.String(), h(w2)}, pack("ProxyUnlock", id, user2, w2)})
	}
	for i, l := range [][]byte{edPub, bipPub, ptPub} {
		d := types.ZeroAddress
		if i == 2 {
			d = user2
		}
		amount, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
		info := &definition.PtlcInfo{Id: ids[i], TimeLocked: user1, TokenStandard: types.ZnnTokenStandard, Amount: amount, ExpirationTime: int64(1700000000 + i), PointType: uint8(i), PointLock: l, Destination: d}
		b, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		v.Info = append(v.Info, string(b))
	}

	for _, r := range v.PointLock {
		lock, _ := hex.DecodeString(r.PointLock)
		v.ReclaimLock = append(v.ReclaimLock, lockRow{r.PointType, r.PointLock, errString(checkReclaimLock(r.PointType, lock)), r.Note})
	}

	bigAmount, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	maxAmount := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	baseTerms := func() *definition.PtlcInfo {
		return &definition.PtlcInfo{Id: ids[0], TimeLocked: user1, TokenStandard: types.ZnnTokenStandard, Amount: big.NewInt(100000000), ExpirationTime: 1700000000, PointType: 1, PointLock: bipPub, Destination: user2}
	}
	termEdits := []struct {
		note string
		edit func(*definition.PtlcInfo)
	}{
		{"base", func(*definition.PtlcInfo) {}},
		{"creator", func(e *definition.PtlcInfo) { e.TimeLocked = user2 }},
		{"open destination", func(e *definition.PtlcInfo) { e.Destination = types.ZeroAddress }},
		{"qsr", func(e *definition.PtlcInfo) { e.TokenStandard = types.QsrTokenStandard }},
		{"amount one", func(e *definition.PtlcInfo) { e.Amount = big.NewInt(1) }},
		{"amount large", func(e *definition.PtlcInfo) { e.Amount = bigAmount }},
		{"amount max", func(e *definition.PtlcInfo) { e.Amount = maxAmount }},
		{"expiration zero", func(e *definition.PtlcInfo) { e.ExpirationTime = 0 }},
		{"expiration byte order", func(e *definition.PtlcInfo) { e.ExpirationTime = 0x0102030405060708 }},
		{"expiration negative", func(e *definition.PtlcInfo) { e.ExpirationTime = -1 }},
		{"ed25519 entry", func(e *definition.PtlcInfo) { e.PointType = 0; e.PointLock = edPub }},
		{"point entry", func(e *definition.PtlcInfo) { e.PointType = 2; e.PointLock = ptPub }},
	}
	for _, c := range chains {
		for rt := uint8(0); rt <= 3; rt++ {
			for k, te := range termEdits {
				if (k+int(rt))%2 == 1 && c != 69 {
					continue
				}
				e := baseTerms()
				te.edit(e)
				v.ReclaimMessage = append(v.ReclaimMessage, reclaimMsgRow{c, rt, termsOf(e), h(definition.GetPtlcReclaimMessage(c, rt, e))})
			}
		}
	}

	edReclaimKey := ed25519.NewKeyFromSeed(seed("reclaim-ed", 0))
	edReclaimPub := edReclaimKey.Public().(ed25519.PublicKey)
	bipReclaimPriv, _ := btcec.PrivKeyFromBytes(seed("reclaim-bip340", 0))
	bipReclaimPub := schnorr.SerializePubKey(bipReclaimPriv.PubKey())
	reclaimLocks := []struct {
		pt   uint8
		lock []byte
		note string
	}{{0, edReclaimPub, "ed25519"}, {1, bipReclaimPub, "bip340"}, {2, ptPub, "point type"}, {0, smallOrderKey, "small order"}, {1, ff, "bip340 off the curve"}, {3, edReclaimPub, "unknown type"}, {0, make([]byte, 31), "short"}}
	for _, c := range []struct {
		pt   uint8
		lock []byte
	}{{0, edPub}, {1, bipPub}, {2, ptPub}, {0, smallOrderKey}} {
		for _, d := range []types.Address{types.ZeroAddress, user1, types.HtlcContract} {
			for _, rl := range reclaimLocks {
				p := definition.CreatePtlcParam{ExpirationTime: 1, PointType: c.pt, PointLock: c.lock, Destination: d}
				err := checkPtlc(p)
				if err == nil {
					err = checkReclaimLock(rl.pt, rl.lock)
				}
				v.CreateWithReclaimLock = append(v.CreateWithReclaimLock, createReclaimRow{c.pt, h(c.lock), d.String(), rl.pt, h(rl.lock), errString(err), rl.note})
			}
		}
	}

	addReclaimSig := func(chain uint64, e *definition.PtlcInfo, rt uint8, lock, sig []byte, note string) {
		rl := &definition.PtlcReclaimLock{Id: e.Id, PointType: rt, PointLock: lock}
		v.ReclaimSignature = append(v.ReclaimSignature, reclaimSigRow{chain, termsOf(e), rt, h(lock), h(sig), errString(verifyPtlcReclaimSignature(e, rl, chain, sig)), note})
	}
	for i, te := range termEdits {
		chain := chains[i%len(chains)]
		e := baseTerms()
		te.edit(e)

		edSig := ed25519.Sign(edReclaimKey, definition.GetPtlcReclaimMessage(chain, 0, e))
		addReclaimSig(chain, e, 0, edReclaimPub, edSig, "ed25519 valid, "+te.note)
		bsig, err := schnorr.Sign(bipReclaimPriv, definition.GetPtlcReclaimMessage(chain, 1, e))
		if err != nil {
			t.Fatal(err)
		}
		bs := bsig.Serialize()
		addReclaimSig(chain, e, 1, bipReclaimPub, bs, "bip340 valid, "+te.note)
		if i > 2 {
			continue
		}

		addReclaimSig(chain^1, e, 0, edReclaimPub, edSig, "ed25519 other chain")
		addReclaimSig(chain^1, e, 1, bipReclaimPub, bs, "bip340 other chain")
		other := baseTerms()
		te.edit(other)
		other.Amount = new(big.Int).Add(other.Amount, big.NewInt(1))
		addReclaimSig(chain, other, 0, edReclaimPub, edSig, "ed25519 other amount")
		addReclaimSig(chain, other, 1, bipReclaimPub, bs, "bip340 other amount")
		other = baseTerms()
		te.edit(other)
		other.ExpirationTime++
		addReclaimSig(chain, other, 1, bipReclaimPub, bs, "bip340 other expiration")
		other = baseTerms()
		te.edit(other)
		other.Destination = user1
		addReclaimSig(chain, other, 1, bipReclaimPub, bs, "bip340 other destination")
		other = baseTerms()
		te.edit(other)
		other.Id = ids[2]
		addReclaimSig(chain, other, 0, edReclaimPub, edSig, "ed25519 same terms, other id")
		addReclaimSig(chain, other, 1, bipReclaimPub, bs, "bip340 same terms, other id")

		bad := append([]byte(nil), bs...)
		bad[40] ^= 0x01
		addReclaimSig(chain, e, 1, bipReclaimPub, bad, "bip340 tampered")
		bad = append([]byte(nil), edSig...)
		bad[63] ^= 0x01
		addReclaimSig(chain, e, 0, edReclaimPub, bad, "ed25519 tampered")
		addReclaimSig(chain, e, 1, bipReclaimPub, bs[:32], "short")
		addReclaimSig(chain, e, 1, bipReclaimPub, append(append([]byte(nil), bs...), 0), "long")

		crossType, _ := schnorr.Sign(bipReclaimPriv, definition.GetPtlcReclaimMessage(chain, 0, e))
		addReclaimSig(chain, e, 1, bipReclaimPub, crossType.Serialize(), "bip340 signed for an ed25519 reclaim lock")
		unlockSig, _ := schnorr.Sign(bipReclaimPriv, definition.GetPtlcUnlockMessage(chain, 1, e.Id, e.TimeLocked))
		addReclaimSig(chain, e, 1, bipReclaimPub, unlockSig.Serialize(), "bip340 unlock message")
		addReclaimSig(chain, e, 0, smallOrderKey, append([]byte{1}, make([]byte, 63)...), "small-order lock with the anyone-signature")
		addReclaimSig(chain, e, 2, ptPub, make([]byte, 32), "point type lock")
		addReclaimSig(chain, e, 3, edReclaimPub, edSig, "unknown type")
		addReclaimSig(chain, e, 1, ff, bs, "bip340 lock off the curve")
	}

	for i, id := range ids {
		rl := reclaimLocks[i%2]
		for j, l := range [][]byte{edPub, bipPub, ptPub} {
			d := types.ZeroAddress
			if j == 2 {
				d = user2
			}
			exp := int64(1700000000 + i*1000 + j)
			v.Abi = append(v.Abi, abiRow{"CreateWithReclaimLock", []interface{}{exp, j, h(l), d.String(), rl.pt, h(rl.lock)}, pack("CreateWithReclaimLock", exp, uint8(j), l, d, rl.pt, rl.lock)})
		}
		w := append(seed("rw", i), seed("rw", i+10)...)
		v.Abi = append(v.Abi, abiRow{"ReclaimWithSignature", []interface{}{id.String(), h(w)}, pack("ReclaimWithSignature", id, w)})
	}

	for i, rl := range reclaimLocks[:2] {
		b, err := json.Marshal(&definition.PtlcReclaimLock{Id: ids[i], PointType: rl.pt, PointLock: rl.lock})
		if err != nil {
			t.Fatal(err)
		}
		v.ReclaimLockInfo = append(v.ReclaimLockInfo, string(b))
	}

	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d messages, %d locks, %d creates, %d witnesses", len(v.UnlockMessage), len(v.PointLock), len(v.Create), len(v.Witness))
}
