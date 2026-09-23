# How Chera works

This guide explains what Chera checks and why, for developers who use the
network every day but are not network engineers. If you want to add a preset
or a signature, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## The big picture

When you type `pip install requests`, several things have to go right:

1. Your computer must be connected to a network at all.
2. Your computer asks a **DNS resolver** "what is the IP address of
   `pypi.org`?" and gets an answer.
3. It opens a **TCP connection** to that IP address on port 443.
4. It starts a **TLS handshake** to encrypt the connection. The very first
   message, the *ClientHello*, contains the name of the site in plain text.
   This field is called **SNI** (Server Name Indication).
5. Over the encrypted connection it sends an **HTTP request** and gets a
   response.

A filter, a misconfigured network or the service itself can break any one of
these steps, and each way of breaking it leaves different fingerprints. Chera
runs each step separately, on purpose, and looks at exactly how it fails.

```
 local network ─► DNS ─► TCP ─► TLS/SNI ─► HTTP ─► (speed) ─► (status page)
```

Every step produces **evidence** (shown with `--verbose`). A small rule engine
then picks the single most likely cause, called the **verdict**, and a
**confidence** level.

## Layer 1: local network

Before blaming anything on the Internet, Chera checks the machine itself:

- **Interfaces**: is there at least one network interface that is up and has an
  address?
- **Default route**: does the operating system know where to send traffic for
  the Internet? Chera "connects" a UDP socket to a documentation address. This
  sends no packets; it only asks the OS to pick a route.
- **Baseline hosts**: it opens TCP connections to a few well-known anycast
  addresses (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`). If none of them answers *and* the
  target does not answer either, the problem is most likely local:
  `LOCAL_NETWORK_DOWN`.

It also looks for things that change how the rest of the results should be
read, and prints a note about them:

- **Proxy environment variables** (`HTTPS_PROXY` and friends). Tools like `pip`
  and `git` use them, but Chera connects directly unless you pass `--proxy`.
  Only the variable *names* are reported, never their values, because they may
  contain passwords.
- **OS proxy settings** (macOS `scutil`, the Windows registry, GNOME settings).
- **VPN interfaces** (`tun0`, `wg0`, `utun3` with an address, "WireGuard
  Tunnel", ...). If a VPN is active, the results describe the path through the
  VPN, not your ISP's.

## Layer 2: DNS

DNS turns names into addresses, and it is the cheapest thing for a filter to
tamper with. Chera asks three kinds of resolvers the same question:

| Resolver | How it is reached | Why |
|---|---|---|
| **System** | Whatever your OS is configured to use | This is what your apps see. |
| **Public, plain UDP** | `1.1.1.1:53`, `8.8.8.8:53` | Plain DNS is unencrypted; if these answers are wrong too, someone on the path is rewriting them. |
| **DNS-over-HTTPS (DoH)** | Cloudflare, Google, Quad9 over HTTPS | Encrypted and authenticated, so it is very hard to tamper with. This is the **reference**. |

The DoH servers are dialed at fixed IP addresses (`1.1.1.1`, `8.8.8.8`,
`9.9.9.9`) so that finding the DoH server does not itself depend on the
resolver being tested. Their certificates are verified as usual.

Chera then compares the answers:

- **Known block-page address**: filtering systems often answer with the
  address of a block page. In Iran, these are commonly `10.10.34.34`,
  `10.10.34.35` and `10.10.34.36`. Any such answer is poisoning, with high
  confidence.
- **Private or reserved address** (`10.x`, `192.168.x`, `127.x`, ...) while DoH
  returns a public address: poisoning, high confidence.
- **Different public address**: this is *not* automatically poisoning. Big
  services use CDNs that give different answers in different places. So Chera
  opens a TLS connection to the system's answer and checks whether it presents
  a valid certificate for the site. If it does, it is just a CDN; if not, it is
  poisoning (medium confidence).
- **"The name does not exist"** (NXDOMAIN) from the system resolver while DoH
  resolves it: poisoning by denial, medium confidence.

### DNS interception

Some networks redirect *all* DNS traffic (UDP port 53) to their own resolver,
whatever address you send it to. Changing your DNS server to `8.8.8.8` then
changes nothing. To detect this, Chera sends one DNS query to
`198.51.100.53`, an address reserved for documentation where no DNS server
exists. **Any answer means DNS is being intercepted.** If poisoned answers are
seen at the same time, the verdict is `DNS_INTERCEPTED` rather than
`DNS_POISONED`, because the fix is different: only encrypted DNS helps.

If the plain UDP queries to public resolvers come back with block-page
addresses while DoH does not, that is also interception (injected answers).

## Layer 3: TCP

Chera connects to port 443 on up to two of the **correct** addresses (from
DoH), not the ones your possibly poisoned resolver returned. This separates
"DNS is lying" from "the real server is unreachable". There are three typical
outcomes:

| Outcome | What it looks like | Usually means |
|---|---|---|
| Connected | SYN, SYN-ACK | The address is reachable. |
| Timeout | No answer at all | Packets are silently dropped: `IP_BLOCKED`. |
| Refused / reset | A TCP RST comes back | Something actively rejects the connection: `CONNECTION_RESET`. |

If the baseline hosts from layer 1 were reachable, a timeout on the target is
reported with high confidence: the network works, just not to this service.

## Layer 4: TLS and SNI

This is where the most common modern filtering happens. The TLS ClientHello
carries the site name (SNI) unencrypted, so a filter can read it and kill the
connection for names on a blocklist, without blocking the IP address (which
may host thousands of other sites).

Chera first does a normal handshake with the real name. If that dies on the
network (reset, silence, or the connection closed right after the ClientHello),
it tries **the same IP address** twice more:

- with a **neutral SNI** (`example.com`), and
- with **no SNI at all**.

If either of those gets any TLS answer from the server (even an error alert or
a certificate for another name), the server is reachable and the only thing
that changed was the name: **`SNI_FILTERED`**, high confidence. If all three
fail the same way, the address itself is blocked or reset.

Chera also **validates the certificate** from the real handshake:

- Signed by an authority your system does not trust, or not valid for the
  site: something in the middle is decrypting your traffic,
  **`TLS_INTERCEPTED`**. Do not type passwords or tokens on that network.
- Valid, but issued by a known TLS inspection product (a corporate firewall or
  an antivirus): also `TLS_INTERCEPTED`, medium confidence.
- Expired: reported with low confidence, because a wrong system clock causes
  the same error.

The neutral-SNI and no-SNI handshakes only run when the real one fails, which
keeps Chera to a handful of connections per service.

## Layer 5: HTTP

If the handshake completes, Chera requests a small URL (like `robots.txt`) from
the verified address and reads up to 64 KB of the response. Redirects are not
followed; the redirect target is inspected instead.

| Response | Verdict |
|---|---|
| Redirect to, or body containing, a known block page | `BLOCK_PAGE` |
| 403/400 from the real service with an "unsupported region" or export-control message | `PROVIDER_GEO_BLOCK` |
| 451 Unavailable For Legal Reasons | `PROVIDER_GEO_BLOCK` (medium) |
| 5xx | `UPSTREAM_OUTAGE` (medium, or high if the status page confirms) |
| Anything else, including 401/404 | `OK`: the network path works |

The distinction between **filtering** and a **provider geo-block** matters a
lot. With filtering, the problem is between you and the service. With a
geo-block, the service itself received your request, saw where it came from
and said no. No DNS setting or local network change will fix that (a package
mirror hosted elsewhere may still help). Chera checks this only after it has confirmed a valid certificate
for the real service, so a block page cannot be mistaken for the provider.

A plain 403 without such a message is **not** treated as a geo-block. Many APIs
answer 403 to anonymous requests.

## Layer 6: throttling (`--speed`)

Throttling is slowing a service down without blocking it. With `--speed`,
Chera downloads up to 1 MB from each healthy target and a 256 KB file from a
baseline host (`speed.cloudflare.com`), and compares:

- **Throughput**: a target below 256 KB/s *and* at least 8 times slower than
  the baseline. This needs at least 64 KB of successful download on both sides,
  otherwise the numbers are too noisy.
- **Handshake time**: a TLS handshake over 1.5 s *and* more than 5 times slower
  than the baseline's.

Either one gives `THROTTLED` with medium confidence: speed measurements are
noisy by nature, so run it again before drawing conclusions.

## Layer 7: outage check

When the path looks clean (TCP and TLS work) but the service misbehaves (5xx,
errors after the handshake), or when no resolver at all knows the name, Chera
asks the service's official status page if one is configured in the preset.
Most developer services use the same status page software, which offers a
`status.json` endpoint. An active incident turns the verdict into
`UPSTREAM_OUTAGE`; if the status page is unreachable, that is noted as
inconclusive evidence.

## Choosing one verdict

The engine walks the layers in order and follows a few principles:

- **The verified path wins over DNS.** If DNS is poisoned *and* the correct
  address is SNI-filtered, the primary verdict is `SNI_FILTERED`, with
  `also: DNS_POISONED`. Fixing DNS alone would not make the service work, so
  suggesting it as *the* fix would be misleading.
- **DNS wins when the path is fine.** If the correct address works perfectly
  but your resolver lies, DNS is exactly what breaks your apps.
- **Local problems come first.** If nothing works, including the baseline
  hosts, the target is not to blame.
- **When in doubt, say so.** `INCONCLUSIVE` with the raw evidence is more
  useful than a confident wrong answer.

## Using a proxy

`--proxy http://host:port` or `--proxy socks5://host:port` sends every TCP
connection Chera makes (baseline, DoH, TCP, TLS, HTTP, status pages) through
that proxy. Plain UDP DNS cannot go through a proxy and still goes out
directly. This is useful to check whether a path through your own proxy works,
and why.

## Being a good network citizen

Chera is a diagnosis tool, not a scanner:

- about 3 connections for a healthy target (TCP, TLS, HTTP), plus DNS queries;
  at most a few more when something fails;
- no retries: a failure is evidence, not something to hammer;
- 8 targets in parallel by default;
- no telemetry, and nothing about you is sent anywhere.
