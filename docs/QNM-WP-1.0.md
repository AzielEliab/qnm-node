# QNM-WP-1.0

Author: Aziel Eliab only.

---

QNM-WP-1.0                                                                                                Aziel Eliab · public work identity only




 Quantum Node Mesh
 QNM-WP-1.0 · fabric concept at 100% · 2026-09-06 · Aziel Eliab · absorbs BUILD-1.0 + TOPO-1.0

    A local process that stays on, hashes through radio failure, airlocks inbound, isolates poison, rotates
    ephemeral IDs in cells of 25 with two bridging members, and never pretends the public Worker is that cell.
    Phoenix waits / re-seals after poison or isolation. Public tunnels and sites die with the pull.

 1. What QNM is not
   • Not qubit hardware. Not a login mesh or account system.
   • Not a VPN, mixnet, or anonymity network.
   • Not AZMail’s ring, not AZNet, not anon-broadcast.
   • Not a Softwares-tab engine. Not enabled by GET /v1/mesh.

 2. Two planes
  Plane                                Default                                Law

  A — local qnm-node                   Process ON. Bearers attempt.           Zero radios: process still ON, ledger appends, bearers empty.
                                                                              After a public pull the local node may keep verifying
                                                                              and appending. It does not climb back onto the hostname.

  B — public rollup                    enabled=false. GET never enables.      Counts only while the public surface exists.
                                                                              Sites pulled → rollup down (die with the pull).
                                                                              No Node Gate. No fake 25 peers. Views/MCP out
                                                                              of QNM-S. Phoenix does not restore this plane.



 3. Bearers
  Bearer                                                       Required       Local default

  Local disk / loopback                                        yes            on — node exists with this alone

  Ethernet / Wi-Fi / internet / Bluetooth / sneakernet         no             attempt — sneakernet is outbox file + hash; operator moves it

 No bearer carries a password. No bearer is a browser login.

 4. Cell
 Full cell = 25 members: 23 leaf + 2 bridges. Bridges are the only inter-cell tethers. Underfill is allowed (1..24) and does not
 invent ghost peers. Overfill refuses join with receipt cell_full. This operator node is one member. Other members are real
 when present — never painted onto a Worker page.

 5. Mesh ID
 assign: mesh_id = SHA-256(prev_id || utc || nonce || cell_id). Session token, not a person. Spend on rotate, poison, or
 phoenix wait / re-seal. Spent IDs never reuse in the same cell. Catalog form: miragegrid/assign (live).
 miragegrid/mesh, vpn-hop, hop, tunnel stay stub. Phoenix does not restore a public hostname.

 6. States
  Kind                    Values                                           Meaning

  Member                  live | isolated | phoenix | spent                spent ID must assign before any later
                                                                           local cell join (not a public hostname restore)

  Cell                    forming | full | degraded | locked               locked after bridge-pair loss until two live bridges sit



 7. Heartbeat, airlock, poison
 Heartbeat payload: cell_id, mesh_id, tip_hash, utc. Three missed intervals → suspect. Suspect plus APG hit → isolate.
 Heartbeat is an act receipt.



Fabric concept 100% · local ON / public rollup dies with pull · 2026-09-06                                                                page 1


QNM-WP-1.0                                                                                          Aziel Eliab · public work identity only




 APG classes: clean pass; reanswer-without-cite refuse; flood refuse; unknown slug or stub-as-live refuse;
 credential/login/cookie refuse; poison/tamper isolate + spend ID + drop tethers.
 If the isolated member was a bridge: rotate both bridges before any inter-cell traffic. Cell → locked until two live bridges
 exist. A single leaf isolate does not halt the cell. Memorial appends spent id, reason, utc, prev tip.

 8. Bridge rotation and phoenix
 Rotate both bridges as a pair on interval, on poison of either, or on operator act. Spent pair cannot carry traffic (refuse
 bridge_spent). A cell with fewer than two live members stays local-only.
 Phoenix: wait / re-seal after poison or isolation. No controller hunt. No public callback. Does not restore a
 public hostname, .uk, Cloudflare tunnel, Worker, or public rollup. A later local assign of a new mesh_id is a
 separate operator act on the local cell — not Phoenix climbing back onto the public name. Phoenix wait is an act.

 9. Tethers and siblings
 Leaf tethers only inside its cell. Bridge tethers only to the other cell’s current bridge pair. Poison cuts first.
 MirageGrid = ID assign. AzielTether = downloaded-copy survival. AZNet and AZMail are other slugs. TemporalLock /
 AZL-LEDGER record every mesh act. FragGate slug=mesh is Worker rollup, not the full node. That rollup dies with the pull.

 10. Never / close tests
   • Do not draw 25 peers on a public page that does not host them.
   • Do not enable mesh with a GET. Do not reuse a spent mesh_id.
   • Do not route inter-cell traffic through a leaf. Do not call MirageGrid a VPN.
   • Do not store passwords in node state. Do not claim qubits.
   • Do not read Phoenix as “bring the .uk / public node back.” Sites pulled → public rollup down.
     Local node may keep verifying and appending. Mesh does not climb back onto the public hostname by itself.
   • Do not make tip preservation depend on a live Worker or public network.
     If network + live data die, the chain survives on cold copies / archive
     re-expand / self-reheal. Local verify / append stay offline.
   • Do not lie to stay alive, adapt, or prevent death. Do not rewrite
     or mutate a published tip. There is no rewrite key. Receipts still
     hash. Verify is without voice. Copies are not all on one tunnel.
   • Concept is closed when both planes, cell math, ID spend, leaf-vs-bridge poison, phoenix wait / re-seal
     without hunt or hostname restore, die-with-pull, split-wires, cold-copy,
     re-expand, reheal, cross-network survival, no-lie, no-rewrite,
     and stub names are specified — they are.
 Specified 2026-09-06. Building qnm-node is implementation. This paper is the concept at 100%. Public identity: Aziel
 Eliab only.

    If the files hold, the name was never the point.




Fabric concept 100% · local ON / public rollup dies with pull · 2026-09-06                                                          page 2
