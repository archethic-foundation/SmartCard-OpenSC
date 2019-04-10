# Open SC Smart card

Interact with a smart card using OpenSC standard (PKCS11)

| Command | Arguments |  Description  |
| ------- | --------- | ------------- |
| hash | [PIN] [DATA] | Hash a data with SHA256 |
| gen-key | [PIN] [CURVE] | Generate a Elliptic keypair (for now only P256 is coded) |
| sign | [PIN] [KEY LABEL] [DATA] | Sign a data using an existing key identified by the key label returned when key generated |