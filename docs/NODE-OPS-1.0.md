# NODE-OPS-1.0

Author: Aziel Eliab only.

---

NODE-OPS-1.0                                                                                               Aziel Eliab · public work identity only




Node operations and security framework
NODE-OPS-1.0 · review of github.com/AzielEliab · 2026-09-06 · Aziel Eliab

   Bulletproof here means smallest public surface, named refuses, isolate-then-phoenix wait / re-seal, no
   auto-heal onto a poisoned ID, and public tunnels / sites that die with the pull. It does not mean an
   unbreakable host or a hostname that climbs back.

1. Fleet review (2026-09-06)
Public repos already point the right way: FragGate hashed registry and refuse ledger; corpus security headers; runtime thin
MCP; qnm-node on 127.0.0.1 with APG, PHOENIX-LOCK wait / re-seal, no account resurrection, no auto-heal; ARK
hosted-never-unlocks; azos/exec stub; MirageGrid hop stubs; AZMail smtp/login stubs. Gaps: BUILD-1.0 docs still say
bearers default-off (amend per QNM-WP-1.0: process ON, public rollup); cell-of-25 dual-bridge rotation not fleet-wired;
Q×act seal not yet the only legal success path on every fraggate_call.

2. Node classes
  Class                Fleet                                   Public surface allowed

  Face                 azieleliab, corpus, godlock             Pages, cite, llms, software mirror while the site exists.
                                                               Pull site / revoke token / drop Worker / kill DNS → the
                                                               public face dies with the pull. Phoenix does not restore it.

  Door                 fraggate, aziel-runtime                 Thin MCP + fraggate_call. GET /v1/mesh never enables.

  Fabric               qnm-node                                Loopback API only. Not on public faces.

  Survival             azieltether                             Counted download. Prefer-central. Not a VPN.

  Overlay              azos, azhub, azinterface                Status / place / cycles. No remote shell.

  Harness              azbot                                   Skill markdown. Queue publish. No browser login.

  Vault                ark, EmbryoLock                         Local only. Hosted unlock/scorch stub.

  Assign               miragegrid                              assign live. mesh/vpn-hop stub.

  Side-net             aznet, azbrowser, azmail                Verify / cite-search / classify. Harvest/login/smtp stub.

  Engine               Locks, CLCE, Z-Solver, receipts, GATE   Listed live ops only.



3. Attack surface law
  • One inbound door. FragGate or loopback. /p/{slug}/{op} is proxy, not exec.
  • Allowlist ops only. Unknown slug = FG-HALLUC-TOOL. Stubs stay refuse.
  • No credentials in process state. token_present only. No browser login.
  • No public enable switch. GET does not change mesh state.
  • qnm-node binds 127.0.0.1. Faces do not proxy that port.
  • Public tunnels and sites DIE WITH THE PULL. A Cloudflare Tunnel lives on token + DNS
    name + account. Pull site / revoke token / drop Worker / kill DNS → cloudflared has
    nowhere legal to land. Restarting cloudflared is operator kit, not this contract; it
    fails if credential or hostname is gone.
  • No vault on the Worker. No auto-heal to a spent mesh_id. No public hostname restore.
  • No account resurrection. Memorial keeps the spend.
  • Identity lock on export. Publish only via official API + AZBOT_PUBLISH=1.
  • Local HTTP keeps nosniff, DENY frames, no-referrer, camera/mic/geo off, tight CSP.

4. Phoenix loop (wait / re-seal — not public restore)
   live → APG miss or tamper → isolate (cut tethers, spend mesh_id) → memorial → PHOENIX-LOCK
   wait / re-seal (local, no controller hunt). Stop there.

  • Phoenix is wait / re-seal after poison or isolation. It is not “bring the .uk / public node
    back.” It does not restore a public hostname, Cloudflare tunnel, Worker, or public rollup.
  • This is not auto-heal. The old ID stays spent. No controller hunt.
  • Sites pulled → public rollup down. Local node may keep verifying and appending.
    Mesh does not climb back onto the public hostname by itself.
  • A later local assign of a new mesh_id is a separate operator act on the local cell — not
    Phoenix reseating the public name, not a failsafe that heals the pulled site.



Node operations + surface law · phoenix wait / re-seal · 2026-09-06                                                                        page 1


NODE-OPS-1.0                                                                                          Aziel Eliab · public work identity only




  • Phoenix does not un-scorch a vault.
  • Poison does not forward across cell edges.
  • Three missed heartbeats = suspect. Suspect + APG hit = isolate.
    Heartbeat loss alone ≠ poison and ≠ apply last packet.
  • Bridge poison rotates both bridges before inter-cell traffic.
  • Held publish queue does not flush across phoenix without a new operator act.
  • Phoenix does not un-pull a site, re-issue a tunnel token, or rewrite DNS.

5. Per-class refuse (minimum)
  Class                  Must refuse

  Face                   Node Gate, IP panel, vault unlock, mesh enable, hostname resurrection

  Door                   Invented slugs, stub ops, runtime_run as agent default

  Fabric                 cell_full join, leaf as inter-cell path, spent ID reuse, public bind

  Survival               vpn / arm / mesh-join stubs; opening a public mesh because central is down

  Overlay                azos/exec; exec of catalog engines from Interface

  Harness                live post without PUBLISH=1; browser login

  Vault                  hosted unlock / encrypt / scorch / wipe

  Assign                 mesh, vpn-hop, hop, tunnel

  Side-net               harvest, login, smtp send, invented visits, deanonymize

  Engine                 any op not on the 1.6.13 allowlist



6. Receipts
Every node writes AZL-LEDGER kinds: boot, heartbeat, refuse, isolate, phoenix, assign, rotate, tether_cut, hold, tick, cite. No model
sentence. No token body.

7. Split the wires
  • Fast 0.5–1s tick: presence + tip hash only. Fixed-size. No body / diff / file on that socket.
  • Payload on a second plane the receiver PULLS — never sender fan-out push.
  • Update is a proof not a timer: cite prev + lockset, fail-closed verify. 777s = dwell after
    valid cite (not wait-then-accept). Clock desync ≠ yes. Ambiguous tip = isolate not merge.
  • Equivocation: same prev, two tips from one node → lock / isolate that peer. No vote-to-reconcile.
    Quorum cannot outvote a broken hash.
  • Emit last locally: announce tip only after own verify. Phoenix is local reboot / WAIT for the
    failed node only — neighbors do not phoenix because a neighbor did. No unsend of unverified body.
    Phoenix is still not public hostname restore. Public tunnels die with the pull.
  • Partition: split brain keeps separate chains, no auto-splice. Rejoin = cite + operator / lockset.
  • The 1s loop and the 777s gate never share a socket.

8. Close tests
  • Public faces have no enable switch and no vault unlock.
  • Door stubs refuse and the refuse is a receipt.
  • qnm-node is not reachable off loopback in default config.
  • Spent mesh_id rejected on later local cell join. Phoenix wait has no outbound hunt packet.
  • Phoenix does not restore a public hostname. Pulled sites stay down (die with the pull).
  • Tick socket carries no body. Fan-out push refused. Cite fail-closed. 1s and 777s sockets stay split.
  • Equivocation locks the peer. Neighbors do not phoenix. No auto-splice. Heartbeat loss does not apply.
  • Held queue does not flush across phoenix without a new act.
  • ARK hosted unlock remains stub. Cell does not halt when one leaf isolates.
Does not add a Node Gate to “see security.” Does not turn MirageGrid into a VPN. Does not publish exploit recipes. Public
identity: Aziel Eliab only.

   If the files hold, the name was never the point.




Node operations + surface law · phoenix wait / re-seal · 2026-09-06                                                                   page 2
