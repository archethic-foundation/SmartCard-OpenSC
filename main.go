package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()
	app.Commands = []cli.Command{
		cli.Command{
			Name:      "hash",
			Usage:     "Generate a hash",
			ArgsUsage: "[pin] [data]",
			Action: func(c *cli.Context) error {

				if len(c.Args()) == 0 {
					return cli.ShowSubcommandHelp(c)
				}

				pin := c.Args().First()
				data := c.Args().Get(1)

				if pin == "" {
					log.Println("Missing pin")
					return cli.ShowSubcommandHelp(c)
				}

				if data == "" {
					log.Println("Missing data")
					return cli.ShowSubcommandHelp(c)
				}

				ctx, session := connect(pin)
				defer ctx.Destroy()
				defer ctx.Finalize()
				defer ctx.CloseSession(session)
				defer ctx.Logout(session)

				hash(ctx, session, []byte(data))
				return nil
			},
		},
		cli.Command{
			Name:      "gen-key",
			Usage:     "Generate a EC key",
			ArgsUsage: "[pin] [curve - (ie.: P256)]",
			Action: func(c *cli.Context) error {

				if len(c.Args()) == 0 {
					return cli.ShowSubcommandHelp(c)
				}

				pin := c.Args().First()
				curve := c.Args().Get(1)

				if pin == "" {
					log.Println("Missing pin")
					return cli.ShowSubcommandHelp(c)
				}

				if curve == "" {
					log.Println("Missing data")
					return cli.ShowSubcommandHelp(c)
				}

				var t keyType
				switch curve {
				case "P256":
					t = p256Key
					break
				default:
					log.Printf("%s curve is not supported", curve)
				}

				ctx, session := connect(pin)
				defer ctx.Destroy()
				defer ctx.Finalize()
				defer ctx.CloseSession(session)
				defer ctx.Logout(session)

				generateECKey(ctx, session, t)
				return nil
			},
		},

		cli.Command{
			Name:      "list-key",
			Usage:     "List EC keys",
			ArgsUsage: "[pin]",
			Action: func(c *cli.Context) error {

				if len(c.Args()) == 0 {
					return cli.ShowSubcommandHelp(c)
				}

				pin := c.Args().First()

				if pin == "" {
					log.Println("Missing pin")
					return cli.ShowSubcommandHelp(c)
				}

				ctx, session := connect(pin)
				defer ctx.Destroy()
				defer ctx.Finalize()
				defer ctx.CloseSession(session)
				defer ctx.Logout(session)

				listECKeys(ctx, session)
				return nil
			},
		},

		cli.Command{
			Name:      "sign",
			Usage:     "Sign data",
			ArgsUsage: "[pin] [pv key label] [data]",
			Action: func(c *cli.Context) error {

				if len(c.Args()) == 0 {
					return cli.ShowSubcommandHelp(c)
				}

				pin := c.Args().First()
				keyLabel := c.Args().Get(1)
				data := c.Args().Get(2)

				if pin == "" {
					log.Println("Missing pin")
					return cli.ShowSubcommandHelp(c)
				}

				if keyLabel == "" {
					log.Println("Missing private key label")
					return cli.ShowSubcommandHelp(c)
				}

				if data == "" {
					log.Println("Missing data")
					return cli.ShowSubcommandHelp(c)
				}

				ctx, session := connect(pin)
				defer ctx.Destroy()
				defer ctx.Finalize()
				defer ctx.CloseSession(session)
				defer ctx.Logout(session)

				sign(ctx, session, keyLabel, []byte(data))
				return nil
			},
		},
		cli.Command{
			Name:      "verify",
			Usage:     "Verify signature",
			ArgsUsage: "[pub key] [data] [sig]",
			Action: func(c *cli.Context) error {

				if len(c.Args()) == 0 {
					return cli.ShowSubcommandHelp(c)
				}

				pubKey := c.Args().First()
				data := c.Args().Get(1)
				sig := c.Args().Get(2)

				if pubKey == "" {
					log.Println("Missing public key")
					return cli.ShowSubcommandHelp(c)
				}

				if data == "" {
					log.Println("Missing data")
					return cli.ShowSubcommandHelp(c)
				}

				if sig == "" {
					log.Println("Missing sig")
					return cli.ShowSubcommandHelp(c)
				}

				bPubKey, _ := hex.DecodeString(pubKey)
				bSig, _ := hex.DecodeString(sig)

				verify(bPubKey, []byte(data), bSig)
				return nil
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func connect(pin string) (ctx *pkcs11.Ctx, ses pkcs11.SessionHandle) {
	ctx = pkcs11.New("/Library/OpenSC/lib/opensc-pkcs11.so")
	err := ctx.Initialize()
	if err != nil {
		panic(err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	ses, err = ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	err = ctx.Login(ses, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}
	return
}

func hash(c *pkcs11.Ctx, s pkcs11.SessionHandle, data []byte) {
	c.DigestInit(s, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)})
	hash, err := c.Digest(s, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(hash))
}

func generateECKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, t keyType) {

	ecParams, _ := asn1.Marshal(keyTypes[t].params)

	id, _ := rand.Int(rand.Reader, big.NewInt(30))
	publabel := fmt.Sprintf("EC_PUB_%s", id.Text(16))
	prvlabel := fmt.Sprintf("EC_PRV_%s", id.Text(16))

	pubKAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}
	pvKAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	pubHandle, _, err := ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubKAttr,
		pvKAttr,
	)
	if err != nil {
		log.Fatal(err)
	}

	pubAttr, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Public key label: %s\n", pubAttr[0].Value)
	curve, err := unmarshalEcParams(pubAttr[1].Value)
	if err != nil {
		log.Fatal(err)
	}
	x, y, err := unmarshalEcPoint(pubAttr[2].Value, curve)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}
	b, _ := x509.MarshalPKIXPublicKey(pubKey)
	log.Printf("Public key: %x\n", b)
}

func unmarshalEcParams(p []byte) (elliptic.Curve, error) {
	for _, i := range keyTypes {
		ep, _ := asn1.Marshal(i.params)
		if bytes.Equal(ep, p) {
			return i.curve, nil
		}
	}

	return nil, errors.New("no supported curve")
}

func marshalEcParams(t keyType) ([]byte, error) {
	switch t {
	case p256Key:
		p, err := asn1.Marshal(keyTypes[t])
		if err != nil {
			return nil, err
		}
		return p, nil
	}

	return nil, errors.New("no supported curve")
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (x *big.Int, y *big.Int, err error) {
	if b[0] != 4 {
		return nil, nil, errors.New("malformed")
	}
	var l, r int
	if b[1] < 128 {
		l = int(b[1])
		r = 2
	} else {
		ll := int(b[1] & 127)
		if ll > 2 { // unreasonably long
			return nil, nil, errors.New("malformed")
		}
		l = 0
		for i := int(0); i < ll; i++ {
			l = 256*l + int(b[2+i])
		}
		r = ll + 2
	}
	if r+l > len(b) {
		return nil, nil, errors.New("malformed")
	}
	pointBytes := b[r:]
	x, y = elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		err = errors.New("malformed")
	}
	return
}

func listECKeys(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) {

	a := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	if err := ctx.FindObjectsInit(session, a); err != nil {
		log.Fatal(err)
	}

	for {
		handles, _, err := ctx.FindObjects(session, 1)
		if err != nil {
			log.Fatal(err)
		}
		if len(handles) == 0 {
			break
		}

		log.Println("-----------------------")
		pubAttr, err := ctx.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Label: %s\n", pubAttr[0].Value)
		curve, err := unmarshalEcParams(pubAttr[1].Value)
		if err != nil {
			log.Fatal(err)
		}
		x, y, err := unmarshalEcPoint(pubAttr[2].Value, curve)
		if err != nil {
			log.Fatal(err)
		}
		pubKey := &ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: curve,
		}
		b, _ := x509.MarshalPKIXPublicKey(pubKey)
		log.Printf("Key: %x", b)
		log.Println("-----------------------")
	}

	defer ctx.FindObjectsFinal(session)
}

func sign(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, data []byte) {

	a := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if err := ctx.FindObjectsInit(session, a); err != nil {
		log.Fatal(err)
	}
	handles, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.FindObjectsFinal(session)
	if len(handles) == 0 {
		log.Fatal("key not found")
	}

	if err := ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, handles[0]); err != nil {
		log.Fatal(err)
	}
	sigBytes, err := ctx.Sign(session, data)
	if err != nil {
		log.Fatal(err)
	}

	n := len(sigBytes) / 2
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sigBytes[:n])
	s.SetBytes(sigBytes[n:])

	sigEcdsa, err := asn1.Marshal(ecdsaSignature{
		R: r,
		S: s,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("signature: %s\n", hex.EncodeToString(sigEcdsa))
}

func verify(pubKey []byte, data []byte, sig []byte) {

	pub, _ := x509.ParsePKIXPublicKey(pubKey)
	ecdsaPub := pub.(*ecdsa.PublicKey)

	var sigEcdsa ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &sigEcdsa); err != nil {
		log.Fatal(err)
	}

	if !ecdsa.Verify(ecdsaPub, data, sigEcdsa.R, sigEcdsa.S) {
		log.Print("Not valid")
	}
	log.Println("Valid")
}

type ecdsaSignature struct {
	R, S *big.Int
}

type keyType int

const (
	p256Key keyType = 1
)

var keyTypes = map[keyType]keyInfo{
	p256Key: keyInfo{
		curve:  elliptic.P256(),
		params: asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	},
}

type keyInfo struct {
	curve  elliptic.Curve
	params asn1.ObjectIdentifier
}
