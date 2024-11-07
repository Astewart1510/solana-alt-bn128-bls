# E2E Example

This is an end-to-end example of BLS signatures over AltBN128. There are 4 steps to this process:

1. Hash to Curve
2. Generate Keypair (offchain)
3. Sign (offchain)
4. Verify (onchain)

## Step 1. Hash to curve

We start with a message:
`"sample" -> 73616d706c65`

The message will then have a counter `\0` appended to it by our hashing function:

`"sample\0" -> 73616d706c6500`

This is the resulting hash:
`a30d14492fe4e906b20d93b882f99379aec8d5a057826b75d4ee440b04db7ed2`

We then check it against the largest multiple of the modulus of the curve below 2^256:
`f1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263`

We do this to normalize our hash to curve function so as to not create a bias in the pRNG. If our value is greater than or equal to the normalization modulus, we will veto the hash, increment the counter and repeat the previous steps. In this case, however, we will find a valid hash on our first try.

We will then modulus the final hash by:

`30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`

Our resulting hash after modulus will be:
`11e028f08c500889891cc294fe758a60e84495ec1e2d0bce208c9fc67b6486fd`

When we decompress it on G1, we get the G1 Point:
`11e028f08c500889891cc294fe758a60e84495ec1e2d0bce208c9fc67b6486fd0d6ac4f2b04c63535037985d348588d3e2a1f3aad7c3354e583bd77a93361364`

## Step 2. - Generate a keypair

We will generate a keypair from the private key:
`216f05b464d2cab272954c660dd45cf8ab0b2613654dccc74c1155febaafb5c9`

The resulting G2 public key should be:
`216f05b464d2cab272954c660dd45cf8ab0b2613654dccc74c1155febaafb5c9`