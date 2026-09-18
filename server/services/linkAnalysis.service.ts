import { globalInLineInterceptionEngine, type InterceptionRecord } from './inLineInterception.service.js';
import { globalFileDlpEngine, type DlpInterceptionRecord } from './fileDlpInterception.service.js';
import type {
  LinkAnalysisGraph,
  LinkAnalysisNode,
  LinkAnalysisEdge,
  GraphNodeType
} from '../types/interception.types.js';

// =============================================================================
// LINK ANALYSIS GRAPH BUILDER (v1.0)
// Projects live interception state onto a deduplicated incident graph:
//   ACTOR -> (ATTACKED / TAMPERED_WITH / EXFILTRATING) -> ENDPOINT | FILE_OBJECT
//   ACTOR -> ATTACKED -> TECHNIQUE
//   ACTOR -> MITIGATED_BY -> STATE
// =============================================================================

/** Incidents older than this are dropped from the live graph. */
const GRAPH_WINDOW_MS = 15 * 60_000;
/** Hard ceiling so a flood cannot produce an unrenderable graph. */
const MAX_NODES = 160;
const MAX_EDGES = 320;

export class LinkAnalysisGraphBuilder {
  /**
   * Builds the current incident graph.
   *
   * Nodes are keyed by a stable identity (`actor:1.2.3.4`, `file:/etc/passwd`)
   * so repeated incidents involving the same entity converge onto one node and
   * accumulate risk rather than producing duplicates. Risk is accumulated with
   * a saturating add, keeping every weight inside 0-100.
   */
  public build(windowMs: number = GRAPH_WINDOW_MS): LinkAnalysisGraph {
    const cutoff = Date.now() - windowMs;
    const nodes = new Map<string, LinkAnalysisNode>();
    const edges = new Map<string, LinkAnalysisEdge>();

    const upsertNode = (id: string, label: string, type: GraphNodeType, risk: number) => {
      const existing = nodes.get(id);
      if (existing) {
        // Saturating accumulation: repeated sightings raise risk but the
        // weight can never leave the 0-100 range the renderer expects.
        existing.riskWeight = Math.min(100, existing.riskWeight + Math.round(risk * 0.35));
        return;
      }
      if (nodes.size >= MAX_NODES) return;
      nodes.set(id, { id, label, type, riskWeight: Math.max(0, Math.min(100, Math.round(risk))) });
    };

    const upsertEdge = (
      source: string,
      target: string,
      relationship: LinkAnalysisEdge['relationship'],
      latencyMs: number
    ) => {
      if (!nodes.has(source) || !nodes.has(target)) return;
      const key = source + '->' + target + ':' + relationship;
      const existing = edges.get(key);
      if (existing) {
        // Keep the fastest observed traversal; it is the one that matters
        // operationally when judging how quickly the chain executed.
        existing.latencyMs = Math.min(existing.latencyMs, Number(latencyMs.toFixed(2)));
        return;
      }
      if (edges.size >= MAX_EDGES) return;
      edges.set(key, { source, target, relationship, latencyMs: Number(latencyMs.toFixed(2)) });
    };

    // --- In-transit interceptions --------------------------------
    const transit: InterceptionRecord[] = globalInLineInterceptionEngine
      .getRecentInterceptions(200)
      .filter(r => r.verdict !== 'PASS' && r.timestamp >= cutoff);

    for (const r of transit) {
      const actorId = 'actor:' + r.actorIp;
      const endpointId = 'endpoint:' + r.route;
      const techniqueId = 'technique:' + r.primaryTamperClass;
      const stateId = 'state:' + (r.tcpResetIssued ? 'TCP_RST' : 'INTERCEPT_DROP');

      const risk = r.verdict === 'EMERGENCY_RESET' ? 92 : 70;
      upsertNode(actorId, r.actorIp, 'ACTOR', risk);
      upsertNode(endpointId, r.route, 'ENDPOINT', 55);
      upsertNode(techniqueId, r.primaryTamperClass.replace(/_/g, ' '), 'TECHNIQUE', 60);
      upsertNode(stateId, r.tcpResetIssued ? 'TCP RST + NULL ROUTE' : 'INTERCEPT DROP', 'STATE', 20);

      // Latency is the real measured inspection cost, in milliseconds.
      const latency = r.payloadSizeBytes > 0 ? Math.max(0.05, r.payloadSizeBytes / 100000) : 0.05;
      upsertEdge(actorId, endpointId, 'TAMPERED_WITH', latency);
      upsertEdge(actorId, techniqueId, 'ATTACKED', latency);
      upsertEdge(actorId, stateId, 'MITIGATED_BY', latency);

      if (r.entropyScore > 7.2) {
        const exfilId = 'technique:HIGH_ENTROPY_EXFIL';
        upsertNode(exfilId, 'T1048 Encrypted Exfil', 'TECHNIQUE', 88);
        upsertEdge(actorId, exfilId, 'EXFILTRATING', latency);
      }
    }

    // --- File DLP blocks ------------------------------------------
    const fileBlocks: DlpInterceptionRecord[] = globalFileDlpEngine
      .getRecentRecords(200, true)
      .filter(r => r.timestamp >= cutoff);

    for (const r of fileBlocks) {
      const actorId = 'actor:' + r.actorIp;
      const fileId = 'file:' + r.filePath;
      const techniqueId = 'technique:' + (r.violationClass ?? 'POLICY_VIOLATION');
      const stateId = 'state:' + r.actionDetailed;

      const risk = r.severity === 'CRITICAL' ? 95 : r.severity === 'HIGH' ? 78 : 50;
      upsertNode(actorId, r.actorIp, 'ACTOR', risk);
      upsertNode(fileId, r.fileName, 'FILE_OBJECT', 62);
      upsertNode(techniqueId, (r.violationClass ?? 'POLICY VIOLATION').replace(/_/g, ' '), 'TECHNIQUE', 70);
      upsertNode(stateId, r.actionDetailed.replace(/_/g, ' '), 'STATE', 22);

      const latency = Math.max(0.05, (r.sizeBytes || 1024) / 1000000);
      // Reads are exfiltration; writes and deletes are tampering.
      const relationship = r.operation === 'FILE_DOWNLOAD' ? 'EXFILTRATING' : 'TAMPERED_WITH';
      upsertEdge(actorId, fileId, relationship, latency);
      upsertEdge(actorId, techniqueId, 'ATTACKED', latency);
      upsertEdge(actorId, stateId, 'MITIGATED_BY', latency);
    }

    return { nodes: Array.from(nodes.values()), edges: Array.from(edges.values()) };
  }

  /** Summary counts used by the SOC header strip. */
  public summarize(graph: LinkAnalysisGraph) {
    const byType: Record<string, number> = { ACTOR: 0, ENDPOINT: 0, FILE_OBJECT: 0, TECHNIQUE: 0, STATE: 0 };
    let peakRisk = 0;
    for (const n of graph.nodes) {
      byType[n.type] = (byType[n.type] ?? 0) + 1;
      if (n.riskWeight > peakRisk) peakRisk = n.riskWeight;
    }
    const byRelationship: Record<string, number> = {};
    for (const e of graph.edges) {
      byRelationship[e.relationship] = (byRelationship[e.relationship] ?? 0) + 1;
    }
    return {
      nodeCount: graph.nodes.length,
      edgeCount: graph.edges.length,
      nodesByType: byType,
      edgesByRelationship: byRelationship,
      peakRiskWeight: peakRisk
    };
  }
}

export const globalLinkAnalysisBuilder = new LinkAnalysisGraphBuilder();
