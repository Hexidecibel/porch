# Porch compared

Porch gets compared with tunnel services, so here is an honest side-by-side.
The short version: ngrok, Cloudflare Tunnel and Tailscale Funnel are hosted
services that put one local port on the internet, with no server of your own
to look after. frp is the open-source engine Porch itself runs on. Porch is
the apps around the tunnel (sharing, uploads, albums, secret forms, E2E
shares, gates, a phone app), on a box and a domain you bring.

If you just need `localhost:3000` on a URL for ten minutes and you don't have
a domain or a server, one of the hosted services is the quicker answer.

| | Porch | ngrok | Cloudflare Tunnel | Tailscale Funnel | frp |
|---|---|---|---|---|---|
| **What it is** | apps + tunnels on your own box | hosted tunnel / API gateway | tunnel into Cloudflare's network | share one port of a tailnet device publicly | tunnel server + client you run |
| **Account with a tunnel provider** | none | required | required for named tunnels; quick tunnels need none | a tailnet (Tailscale account) | none |
| **Your own domain** | yes | Pay-as-you-go plan and up | yes, a zone on Cloudflare | no, `<name>.<tailnet>.ts.net` only | yes |
| **Where TLS ends** | your box | ngrok's cloud (HTTPS endpoints) | Cloudflare's edge | your device | where you configure it |
| **Open source** | yes (MIT) | agent closed (1.x was open, unmaintained) | `cloudflared` yes (Apache-2.0); the network is a service | client mostly; coordination server closed | yes (Apache-2.0) |
| **Link rules** | expiry, password, guest link, max opens, burn after one | basic auth, OAuth/OIDC, JWT, IP rules (Traffic Policy) | identity login via Cloudflare Access | — | HTTP basic auth |
| **Send things** (file viewer, galleries, music, paste) | built in | — | — | — | — |
| **Receive things** (uploads, photo albums, one-time secret forms) | built in | — | — | — | — |
| **End-to-end encrypted shares** (server holds ciphertext only) | yes (`porch share --e2e`) | — | — | — | — |
| **Ask to reopen / ask for access** | yes, with push notifications | — | — | — | — |
| **Phone control app** | yes (the Porch app, installable web app) | — | — | — | — |
| **Request inspector + replay** | yes | yes | — | — | — |
| **Needs your own server** | **yes**: a home box (plus a $4-5 relay behind CGNAT) or a VPS | no | no | no | yes, a public one |
| **Needs a domain** | **yes** | no | yes, for named tunnels | no | for subdomain routing |
| **Price** | free; your box + domain | free tier (1 dev domain, 1 GB out); $10 and $20/month plans | free tunnels; Access free up to 50 users | all plans, incl. free; fixed bandwidth limits | free |
| **Maturity** | **new** (2026) | established company | established company | beta, established company | mature, widely deployed |

"—" means the product doesn't offer it as a built-in feature, as far as its
public docs show. Most of these services can front any app you run yourself,
so you can always bring your own upload page or gallery; Porch's point is that
you don't have to.

## Where the others are stronger

- **No hardware, no domain.** ngrok, Cloudflare quick tunnels and Funnel work
  from a laptop in a minute. Porch needs a box people can reach and a domain.
- **Scale and reach.** Cloudflare and ngrok run global edges, DDoS
  protection and load balancing. A Porch box serves visitors at the speed of
  its own uplink.
- **Private networks.** Tailscale is a whole mesh VPN; Funnel is a small part
  of it. Porch only does the public side.
- **Track record.** All four have years of production use. Porch is new; see
  the [security model](security.md) for what it does and doesn't promise.

## Where Porch is different

- **Nothing in the middle.** TLS ends on your box. In relay mode the relay
  forwards encrypted TCP and never holds your key
  ([guides](guides/README.md#cost-and-comparison)).
- **The apps are the point.** Every link is a *door* with its own rules, and
  most doors are a finished page: a viewer, a gallery, an upload page, a
  one-time secret form. See the [showcase](https://hexidecibel.github.io/porch/showcase/).
- **Your phone runs it.** Doors, devices, invites and requests from the
  [Porch app](pocket-app.md), with passkey step-up for risky actions.

Facts about the other products were checked against their own documentation
and pricing pages in October 2026. Plans change; if a row is out of date,
please open an issue.
