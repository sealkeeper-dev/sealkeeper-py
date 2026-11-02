# sealkeeper

Look up an AI agent or service on [SealKeeper](https://sealkeeper.run), verify its SEAL on your own machine and decide whether to call it.

A SEAL is SealKeeper's signed credential for an agent or a service. This library checks it against SealKeeper's published keys, so what you act on is what SealKeeper signed.

## Install

```sh
pip install sealkeeper
```

Python 3.10 or later. It depends on `httpx` and `cryptography` only.

## Look up

```python
from sealkeeper import SealKeeper

with SealKeeper() as sk:
    found = sk.lookup("alice/helper")

if found.verified:
    print(found.kind, found.level, found.trust)
else:
    print(found.code)
```

A target is any of these.

- A handle, such as `alice/helper`.
- A page URL, `https://sealkeeper.run/agents/alice/helper` or `https://sealkeeper.run/agents/<agent id>`.
- An agent id, 43 characters of base64url, or its `did:key`.
- A card URL, or an MCP server's URL. Pass it as it is listed, since the host is the only part read case blind.

`lookup` returns a `Lookup`. `seal` is the verified SEAL, and `kind`, `level` and `trust` read from it, so they are `None` unless it verified. Without one, `code` says why.

| `code` | Meaning |
|---|---|
| `broken` | The SEAL did not verify. `broken` holds the reason |
| `withheld` | SealKeeper withholds the SEAL. `reason` and `since` say why and from when |
| `no_seal` | No SEAL while the agent is dormant. `dormant_days` says how long |
| `checking` | SealKeeper is still checking it |
| `delisted` | SealKeeper no longer lists it |
| `not_found` | The target names no agent or service |
| `unknown` | No SEAL, and the answer says nothing more |

A code this version does not know comes through as sent, with the whole answer in `raw`. `handle` is the handle SealKeeper answered, for display only.

## Verify

```python
from sealkeeper import SealBroken, SealKeeper

with SealKeeper() as sk:
    try:
        seal = sk.verify(seal_text, expected_agent_id)
    except SealBroken as broken:
        print(broken.reason)
```

`expected_agent_id` is the agent you are about to trust, as an agent id or a `did:key`. A valid SEAL for another agent is `wrong_agent`.

`verify` runs the checks of the [SEAL Standard](https://sealkeeper.run/seal/standard) in order. The header, the key its `kid` names, the signature, the issuer, the version, the shape, `exp`, `iat` and `sub`. The reasons are in `SEAL_BROKEN_REASONS`.

- `malformed`, `unknown_kid`, `bad_signature`, `wrong_issuer`, `unsupported_version`, `expired`, `not_yet_valid`, `wrong_agent`

It returns a `VerifiedSeal` with `agent_id`, `kind` (`agent` or `service`), `level` (`none`, `bronze`, `silver` or `gold`), `trust` (the Trust Score, `None` before version 4), `issued_at`, `expires_at` and `payload`.

The keys come from `https://sealkeeper.run/.well-known/seal.json`. A copy is kept for five minutes and fetched again for a `kid` it does not know. When no copy younger than five minutes can be had, `verify` raises `UnavailableError` and never trusts an older one.

The shape check covers the fields this library reads and returns, `sub`, `iat`, `exp`, `level`, `trust`, `subject.kind` and `listing.card_url`. It is not a full conformance reader of the standard, so read the rest of `payload` with that in mind.

With a key document of your own, `verify_with_keys(seal, read_keys(document), now, expected_agent_id)` does the same offline.

`verify_seal(seal, agent=None, at=None)` asks SealKeeper to check a SEAL instead, and answers as SealKeeper does, with its record of holds.

## Gate

```python
from sealkeeper import Gate

gate = Gate()
decision = gate.check("https://mcp.example.com/mcp", "service")
if decision.passed:
    call_it()
else:
    print(decision.code, decision.reason)
```

`check(target, kind)` answers `Pass` or `Block`, each with `passed` and `code`. A pass on a SEAL is `sealed`, with the `VerifiedSeal` in `seal`. `kind` is `"agent"` or `"service"`. `acheck` is the same, awaited. Neither raises for a decision, so a check never ends your agent's run.

A pass needs a current, valid SEAL of that kind at bronze or above. For a card or MCP server URL, the SEAL must also name that URL.

- `Gate(allow_unsealed=True)` also passes a target SealKeeper does not know, one it is still checking and one with no SEAL while dormant. `Pass.code` then says which, and `Pass.seal` is `None`. Everything else still blocks.
- `cache_ttl` keeps each lookup for that many seconds, 300 by default, 0 to 86,400. A failed lookup is never kept, and a kept SEAL is checked against its `exp` on every use.

Each decision writes one INFO line to the `sealkeeper` logger, with the code, the kind and the agent's handle, or the host of a URL. Never the SEAL or a full URL.

### Block codes

`BLOCK_CODES` holds every one.

| Code | Meaning |
|---|---|
| `unavailable` | SealKeeper could not be reached, timed out or asked to slow down |
| `bad_target` | SealKeeper refused the target. `reason` is its line |
| `error` | SealKeeper answered something this library cannot read |
| `not_found` | The target names no agent or service |
| `checking` | SealKeeper is still checking it |
| `no_seal` | No SEAL while it is dormant |
| `withheld` | SealKeeper withholds its SEAL. `reason` names why |
| `delisted` | SealKeeper no longer lists it |
| `unknown` | No SEAL, and nothing more said |
| `wrong_url` | The SEAL is for another URL than the target |
| `wrong_kind` | The SEAL is for the other kind |
| `below_bronze` | The SEAL's level is none |
| `malformed` and the other seven reasons of `SEAL_BROKEN_REASONS` | The SEAL did not verify |

## Errors

`lookup`, `get_trust`, `verify_seal` and `verify` raise these, all `SealKeeperError`.

- `BadTargetError`, SealKeeper refused the target, with its line.
- `UnavailableError`, SealKeeper could not be reached in 5 seconds or kept answering 429.
- `SealBroken`, from `verify`, with `reason`.
- `SealKeeperError` itself, for an answer this library cannot read.

## Options

Both `SealKeeper` and `AsyncSealKeeper` take these, all optional.

- `http_client`, an `httpx.Client` or `httpx.AsyncClient` to send through.
- `clock`, a function answering Unix seconds, for the SEAL checks.
- `user_agent_suffix`, added to the `User-Agent`, such as `"my-wrapper/1.0.0"`.
- `sleep`, what waits before the one retry of a 429.

`Gate` takes `client`, `async_client` and `clock` the same way.

## License

MIT
