# Chronometry
[Chronometry](chronometry.io) is a tamper-proof platform for hackers and bug bounty hunters to record & keep track of Proof-of-Hacks (PoH). The word Chronometry refers to the science of accurate time measurement.

"Proof of Hack" refer to the evidence or demonstration that a hacker has successfully exploited a vulnerability in a system or application. This proof is used to verify the authenticity of the vulnerability report.

Hackers usually tweet hashes as a means of sharing the details of a specific exploit or vulnerability with other members of the hacking community. The hash is a unique representation of a Proof-of-Concept file or a vulnerability report submitted to platforms like HackerOne/Yokai/ZDI, and can be used to confirm the authenticity of the data or to check if it has been tampered with. 

By generating a hash of the report before it is submitted and recording it on [Chronometry](chronometry.io), a Hacker can create a unique and verifiable fingerprint of the report that can be used to confirm its authenticity at a later time. This can be useful for resolving disputes or for providing proof of discovery in cases where multiple parties claim to have reported the same vulnerability.

The most common forms of proof-of-hack include:

- A detailed description of the vulnerability and how it can be exploited
- A proof-of-concept (PoC) exploit code
- A video or screenshot demonstrating the successful exploitation of the vulnerability
- A detailed explanation of the impact of the vulnerability
- A description of the steps taken to mitigate the vulnerability

Chronometry uses [Trillian](https://github.com/google/trillian)

Trillian implements a Merkle tree whose contents are served from a data storage layer, to allow scalability to extremely large trees. On top of this Merkle tree, Trillian provides the following:

An append-only Log mode, analogous to the original Certificate Transparency logs. In this mode, the Merkle tree is effectively filled up from the left, giving a dense Merkle tree.


## Usage
### Installation
#### Client
```sh
$ git clone github.com/ant4g0nist/chronometry
$ cd chronometry
$ 
```

### Key Generation
Generate a new Chronometry key pair:

```sh

# Keys will be saved in ~/.chronometry/
chronometry keys generate

# Keys will be saved in ~/mykeys/
chronometry keys generate --output ~/mykeys/

# Keys will be saved in ~/mykeys/ with the name mykeys
chronometry keys generate --output ~/mykeys/ --name mykeys

# Keys and encrypt them with a passphrase
CHRONOMETRY_PASSWORD=myPassPhrase chronometry keys generate --output ~/mykeys/ --name mykeys

# Keys and encrypt them with a passphrase
chronometry keys generate --output ~/mykeys/ --name mykeys --passphrase mypassphrase

# Keys non-interactively
chronometry keys generate --output ~/mykeys/ --name mykeys --passphrase mypassphrase --yes
```


### Report
Chronometry uses `yaml` format specified below to create a report.
```yaml
version: 102

author:
  name: John Doee
  email: john@doe.io
  url: https://yokai.network/hacker/john-doe

platform: Yokai

title: Sample Vulnerability Report in function X

description: 
  This is a sample vulnerability report in function X. It is intended to demonstrate the
  capabilities of the vulnerability report format. 
  
  This is a multi-line description. It is intended to demonstrate the
  capabilities of the vulnerability report format.

severity: Critical

# extra attributes
attributes:
  - name: Attribute 1
    value:
      This is a multi-line attribute value. It is intended to demonstrate the
      capabilities of the vulnerability report format.
  - name: Attribute 2
    value: Value 2
  
attachments:
  - name: Sample Attachment 1
    # path can be a local PoC file 
    path: ./examples/sample.zip
  - name: Sample Attachment 2
    # # path can be a local PoC file
    path: ./examples/file_example_MP4_480_1_5MG.mp4
```

The above report format is used by Chronometry client to create a signature that can be used to verify the authenticity of the report. The report is signed using the private key of the user. The signature is then used to generate a PoH of the report. The PoH is then recorded on the Trillian Log. 

### Generate a PoH
```sh
go run cmds/cmetry-cli/main.go sign -h
Sign the supplied Vulnerability Report. This command will generate a signed blob that can be posted to the Chronometry's public data store.

Usage:
  chronometry-cli sign [flags]

Flags:
  -b, --blob string               write the blob to FILE
  -h, --help                      help for sign
      --input string              The folder to search the public and private key files. (default "~/.chronometry")
      --name string               The base name for the public and private key files. The public key file will have the suffix '.pub' appended to the name. (default "id_ed25519")
  -o, --output-signature string   write the signature to FILE
      --passphrase string         The passphrase to decrypt the private key.
  -f, --reportFile string         A vulnerability report file to calculate generate the signature for.
  -a, --show-author               Show the author's name in the report. By default, the author's name is hashed and included in the signature
```

If you have a report file `examples/sample-report.yaml` you can generate a PoH using the following command:
```sh
go run cmds/cmetry-cli/main.go sign -f examples/sample-report.yaml --passphrase password -b output.poh -a
```

`-a` flag is used to include the author's name in the report. By default, the author's name is hidden (so, author name in the PoH records will be `Anonymous`), only hash of the name is included in the signature. 

```sh
cat output.json
{
 "Report": {
  "Version": "N4NPLyV2LyPh90pTHL5EXbc9Z2Xr5gh4p9--zX1K9uE=",
  "Title": "HsAB38Ftx9vQ-y_-7RnbAsXgwGpputFo19ZFtEx_yAQ=",
  "Description": "CimMqMLdUqYVqHiXtuVe7U0ZfuVxtsltuSVVbS1UVfA=",
  "Attributes": "G8acHYAMEp7uwz2eMyOTRuQEQLpCqVUFRvz9zySTSq8=",
  "Author": "Anonymous",
  "AuthorDetailsHash": "eDMQAUUWZFUUpMjN1Ujb_Fjw6BDFNM0fRJ1HxFPX-v4=",
  "Platform": "fDIzedm5COBGBl4mq24iXixHI8OO9j2gEKel34SyPKs=",
  "Severity": "Qn3SlpvRQL7DwbzHmD2pgvSBWTjNRRCtCyutSKxbVfk=",
  "Attachments": "IqamhAdadrzbur3x_7GOYVrwHn6xFeCz1E1MjwqJ8m0="
 },
 "PublicKey": "Hp2mvMiSc1XFhBUGxaQc0br/CtJrNBkiMTUoORCzRP4=",
 "Signature": "JMFwICkm2mtVLhAYFi5LaCvfnQt8XY7LwonkNgx08jCX3kMjGg6iJoeATyGFelyN0z2X4BxEyq1N9ojaNimVAg=="
}
```

### Verify a PoH
You can verify a PoH using the following command:
```sh
❯ go run cmds/cmetry-cli/main.go verify -r output.poh
⌛️Verifying signature...
publicKey: Hp2mvMiSc1XFhBUGxaQc0br/CtJrNBkiMTUoORCzRP4=
signature: JMFwICkm2mtVLhAYFi5LaCvfnQt8XY7LwonkNgx08jCX3kMjGg6iJoeATyGFelyN0z2X4BxEyq1N9ojaNimVAg==
✅Signature verification successful
```

You can also verify a PoH record on the Chronometry's Trillian Log Server using the following command:
```sh
❯ go run cmds/cmetry-cli/main.go verify -i 12 -s http://localhost:8008
publicKey: Hp2mvMiSc1XFhBUGxaQc0br/CtJrNBkiMTUoORCzRP4=
signature: sWKfA4/aD1hV0h36QpBEeIh5MTAM8IHPFNND2WFbz3m+3z60Ls6Srh6DkHIyyvQzgW7WjS8M/fpU/Fyprcu3Dw==
⌛️Verifying signature...
✅Signature verification successful
```

### Record a PoH
To record the generated PoH on the Chronometry's Trillian Log Server, you can run a command similar to the following:
```sh
❯ go run cmds/cmetry-cli/main.go record -f output.json -s http://localhost:8008
ETag: 29912308828015d2920df6861b0dbda4080aad6e4e5e91f75433969e31161c07
Location: localhost:8008/record/7a19e0d4eaed06f829912308828015d2920df6861b0dbda4080aad6e4e5e91f75433969e31161c07
Payload:
  Key: 7a19e0d4eaed06f829912308828015d2920df6861b0dbda4080aad6e4e5e91f75433969e31161c07
  IntegratedTime: 1690202999
  LogID: 7a19e0d4eaed06f8
  LogIndex: 101
  Verification:
    InclusionProof:
      Checkpoint: bG9jYWxob3N0IC0gODc5ODMxMDU1MjEyNDA2NTUyOAoxMDIKM0dueGd5dFJaVU9oNTNZWDREQ2RpM1ZBc2tTbVB0K045UEZDOStlOVk2OD0KVGltZXN0YW1wOiAxNjkwMjAyOTk5NzQ2Njc1MDAwCgrigJQgbG9jYWxob3N0IFBLNmJZY2dkQUNiOE1RZis3aStQUkRYdFdJZTFvaHZtRlF2enFhMURYYk02dVFvY3RndTdMTVVNd0ZGOHFSd3ROdlhLdEFSajBaZlRGRFZZUXJZS0pBUFRod1E9Cg==
      Hashes: [f7f2756ddaa8b2a8dce8d74be128d9e11a05a9d202090cd9e24a12cca1b56ecb 297c6f09de2dfed365a627dc336d376f9fe070c76b02f61911d2d6c2e4d659a5 0d0b2be6e839f3c0d1ca14536f67f899d3ceab56c720fbb0f9dec9cd4bd3fe27 c1f81d2881d8f11caaf4080abf8941bda11015be838ceb0189eb44fceffde178]
      LogIndex: 101
      RootHash: dc69f1832b516543a1e77617e0309d8b7540b244a63edf8df4f142f7e7bd63af
      TreeSize: 102
    SignedEntryTimestamp: OS3bTQYxWzSFic/VL2WcJ0wOQ4ky+2kVg9DAKTszrAu4rUnr9xL4u60CCXhpbSVPnf2YwPCMKMSLuCEXM/jiCQ==
Report uploaded successfully
```

---
- Author: [ant4g0nist](https://twitter.com/ant4g0nist)


## Contributions
- SigStore