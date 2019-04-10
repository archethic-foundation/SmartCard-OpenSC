package main

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
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

	//Marshal the curve to use
	marshaledOID, _ := asn1.Marshal(keyTypes[t])

	id, _ := rand.Int(rand.Reader, big.NewInt(30))
	publabel := fmt.Sprintf("EC_PUB_%s", id.Text(16))
	prvlabel := fmt.Sprintf("EC_PRV_%s", id.Text(16))

	pubKAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
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

	pubHandle, pvHandle, err := ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubKAttr,
		pvKAttr,
	)
	if err != nil {
		log.Fatal(err)
	}

	a := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}

	pubV, err := ctx.GetAttributeValue(session, pubHandle, a)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Public key label: %s\n", pubV[1].Value)
	log.Printf("Public key handle: %d\n", pubHandle)

	pvV, err := ctx.GetAttributeValue(session, pvHandle, a)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Private key label: %s\n", pvV[1].Value)
	log.Printf("Private key handle: %d\n", pvHandle)
}

func sign(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, data []byte) {

	a := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
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
	log.Printf("signature: %s\n", hex.EncodeToString(sigBytes))
}

type keyType int

const (
	p256Key keyType = 1
)

var keyTypes = map[keyType]asn1.ObjectIdentifier{
	p256Key: asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
}
