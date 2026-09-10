# Where the ECCp-97 parameters came from

`rounds/eccp97.json` is Certicom's ECCp-97 challenge, unchanged. It is not a curve
we generated.

## Source

The parameters are the constants compiled into the client that actually solved the
challenge in 1998 — the BT Labs / INRIA effort led by Robert Harley, Adrian Escott,
John Sager, Alex Selkirk and Dimitris Tsapakidis:

    http://cristal.inria.fr/~harley/ecdl4/32bit/v094/eccp97a.c   (dated 1998)

In that file the values appear as 96-bit-plus-carry words, `{ex, hi, mi, lo}`
meaning `ex·2⁹⁶ + hi·2⁶⁴ + mi·2³² + lo`:

| name | source symbol | hex |
|---|---|---|
| field prime `p` | `mod` | `0x16ea1595ed21ae4d8d8420e35` |
| group order `n` | `ord` | `0x16ea1595ed21ae98fb6cca20d` |
| `a` | `a` | `0x47370916a603b07657c305c4` |
| `b` | `b` | `0x1124df86d04064f503d9925af` |
| `G.x` | `x1` | `0xd5d9e9dff58a9232a2749ebc` |
| `G.y` | `y1` | `0x11b34ae5aab7c7ae55d6abdb5` |
| `Q.x` | `x2` | `0xdf7e84c42fef50c5316c508a` |
| `Q.y` | `y2` | `0xf259bc583729da0fe8b97336` |

The result announcement is at
`http://cristal.inria.fr/~harley/ecdl4/ECCp-97.submission.text`:

> The solution to Certicom's ECCp-97 problem is the residue class of
> `1 6C86AA7C ACF69F1D D28B3E2F` modulo `1 6EA1595E D21AE98F B6CCA20D`.
> The calculation was carried out in 53 days by a group of 588 people and 1288
> machines in more than 16 countries. It was found after 186,364 Distinguished
> Points … a collision was detected at 23:38 GMT on Monday 16th of March 1998.

The modulus quoted there is exactly the `n` above, which is the first check that
these are the right constants.

## Independent verification

`tests/test_eccp97.py` re-derives everything from the round file alone and asserts:

- `p` and `n` are prime, 97 bits each
- the curve is nonsingular, and `n` lies inside the Hasse interval for `p`
- `G` and `Q` are on the curve, and `n·G = n·Q = ∞`
- `n ≠ p`, and the embedding degree is above 20
- **`k·G = Q` for `k = 0x16c86aa7cacf69f1dd28b3e2f`**, the answer published in 1998

The last one is decisive. Nobody can produce a `k` that maps this `G` to this `Q`
without either solving the problem or being handed the real answer, so a curve that
satisfies it with the historical constant is the historical curve.

## Why run a solved problem

Because the finish line is known. ECCp-97 has been public since March 1998, which
means this round can check its own answer: when the network reports a collision,
the `k` it derives has to be that number. A search whose result can be checked
against a twenty-eight-year-old published one is the right thing to run before a
search whose result cannot be checked against anything.

Knowing the answer does not help anyone claim credit. Credit is paid for
distinguished points whose walks replay from `PRF(round_id, pubkey, t)`, and a
walker does not get to choose the coefficients those walks arrive with. The
published `k` produces no valid points, no valid openings and no forged collision.

Certicom's own term for the sub-109-bit problems is *exercises*. That is what this
is: the parameters are real, the difficulty is real, the prize is not.
