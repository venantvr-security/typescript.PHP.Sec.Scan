import {HolonEdge, HolonGraph, HolonNode, HolonStyling, TaintFlowEntry} from './types';

const NODE_W = 210;
const NODE_H = 64;
const COL_GAP = 90;
const ROW_GAP = 30;
const MARGIN = 20;

type TaintKind = 'source' | 'tainted' | 'sanitized' | 'sink' | 'usage';

const STYLING: Record<TaintKind, HolonStyling> = {
    source: {fill: '#ffe0b2', stroke: '#ef6c00', strokeWidth: 2, opacity: 1},
    tainted: {fill: '#fff9c4', stroke: '#f9a825', strokeWidth: 2, opacity: 1},
    sanitized: {fill: '#e8f5e9', stroke: '#2e7d32', strokeWidth: 2, opacity: 1},
    sink: {fill: '#ffcdd2', stroke: '#c62828', strokeWidth: 2, opacity: 1},
    usage: {fill: '#eceff1', stroke: '#90a4ae', strokeWidth: 1, opacity: 1}
};

const ARCHIMATE: Record<TaintKind, string> = {
    source: 'Source',
    tainted: 'Variable teintée',
    sanitized: 'Désinfectée',
    sink: 'Sink (vulnérabilité)',
    usage: 'Fonction'
};

interface TaintNode {
    id: string;
    kind: TaintKind;
    name: string;
    file: string;
}

interface TaintEdge {
    source: string;
    target: string;
    relationType: 'Flux' | 'Désinfection' | 'Vulnérabilité' | 'Usage';
    name: string;
}

/**
 * Construit un graphe de teinte (source → variable → sink) au format Holon à
 * partir du journal de flux produit par {@link TaintAnalyzer.getTaintFlow}.
 * La mise en page est en couches de gauche à droite : sources, variables
 * (par profondeur de propagation), puis sinks / usages.
 */
export function exportTaintGraph(flow: TaintFlowEntry[], exportedAt: string): HolonGraph {
    const nodes = new Map<string, TaintNode>();
    const edges: TaintEdge[] = [];
    const seenEdges = new Set<string>();
    // Dernier identifiant de nœud connu pour un nom de variable, par fichier.
    const varNode = new Map<string, string>();

    const ensure = (node: TaintNode): string => {
        const existing = nodes.get(node.id);
        if (!existing) {
            nodes.set(node.id, node);
        } else if (node.kind === 'sanitized' && existing.kind === 'tainted') {
            existing.kind = 'sanitized';
        }
        return node.id;
    };

    const addEdge = (source: string, target: string, relationType: TaintEdge['relationType'], name: string): void => {
        if (source === target) {
            return;
        }
        const key = `${source}|${target}|${relationType}`;
        if (seenEdges.has(key)) {
            return;
        }
        seenEdges.add(key);
        edges.push({source, target, relationType, name});
    };

    const varId = (file: string, name: string) => `var:${file}:${name}`;

    for (const entry of flow) {
        if (entry.action === 'assignment') {
            const kind: TaintKind = entry.origin === 'sanitized' ? 'sanitized' : 'tainted';
            const id = ensure({id: varId(entry.file, entry.variable), kind, name: entry.variable, file: entry.file});

            if (entry.origin === 'source') {
                const srcId = ensure({
                    id: `src:${entry.file}:${entry.source}`,
                    kind: 'source',
                    name: entry.source,
                    file: entry.file
                });
                addEdge(srcId, id, 'Flux', '');
            } else if (entry.origin === 'propagation' || entry.origin === 'sanitized') {
                const relation = entry.origin === 'sanitized' ? 'Désinfection' : 'Flux';
                for (const predId of predecessorsIn(entry.source, entry.file, nodes, varNode, entry.variable)) {
                    addEdge(predId, id, relation, '');
                }
            }

            varNode.set(`${entry.file}:${entry.variable}`, id);
        } else if (entry.action === 'function_parameter') {
            const fromId = ensure({id: varId(entry.file, entry.variable), kind: 'tainted', name: entry.variable, file: entry.file});
            if (entry.isVulnerable) {
                const sinkId = ensure({id: `sink:${entry.file}:${entry.details}`, kind: 'sink', name: entry.details, file: entry.file});
                addEdge(fromId, sinkId, 'Vulnérabilité', entry.vulnType ?? '');
            } else {
                const fnId = ensure({id: `fn:${entry.file}:${entry.details}`, kind: 'usage', name: entry.details, file: entry.file});
                addEdge(fromId, fnId, 'Usage', entry.details);
            }
        }
    }

    return assemble(Array.from(nodes.values()), edges, exportedAt);
}

/** Nœuds de variables existants (même fichier) dont le nom apparaît comme jeton dans `source`. */
function predecessorsIn(
    source: string,
    file: string,
    nodes: Map<string, TaintNode>,
    varNode: Map<string, string>,
    exclude: string
): string[] {
    const preds: string[] = [];
    for (const node of nodes.values()) {
        if (node.file !== file || node.name === exclude) {
            continue;
        }
        if (node.kind !== 'tainted' && node.kind !== 'sanitized' && node.kind !== 'source') {
            continue;
        }
        if (node.kind === 'source') {
            continue; // les sources ne se propagent que via leur affectation directe
        }
        if (new RegExp(`${escapeRegExp(node.name)}(?![A-Za-z0-9_])`).test(source)) {
            preds.push(node.id);
        }
    }
    return preds;
}

function assemble(taintNodes: TaintNode[], taintEdges: TaintEdge[], exportedAt: string): HolonGraph {
    const rank = computeRanks(taintNodes, taintEdges);
    const byRank = new Map<number, TaintNode[]>();
    for (const node of taintNodes) {
        const r = rank.get(node.id) ?? 0;
        const bucket = byRank.get(r) ?? [];
        bucket.push(node);
        byRank.set(r, bucket);
    }

    const geometry = new Map<string, {x: number; y: number}>();
    for (const [r, group] of byRank) {
        group.forEach((node, i) => {
            geometry.set(node.id, {
                x: MARGIN + r * (NODE_W + COL_GAP),
                y: MARGIN + i * (NODE_H + ROW_GAP)
            });
        });
    }

    const nodes: HolonNode[] = taintNodes.map(node => {
        const pos = geometry.get(node.id) ?? {x: MARGIN, y: MARGIN};
        return {
            id: node.id,
            parentId: null,
            type: 'node',
            geometry: {x: pos.x, y: pos.y, w: NODE_W, h: NODE_H},
            styling: STYLING[node.kind],
            data: {
                name: node.name,
                archimateType: ARCHIMATE[node.kind],
                documentation: `${ARCHIMATE[node.kind]} — ${node.file}`
            }
        };
    });

    const edges: HolonEdge[] = taintEdges.map((edge, index) => ({
        id: `edge-${index + 1}`,
        sourceId: edge.source,
        targetId: edge.target,
        routing: 'straight',
        data: {relationType: edge.relationType, name: edge.name}
    }));

    return {
        version: '1.0',
        exportedAt,
        nodes,
        edges,
        metadata: {
            nodeCount: nodes.length,
            edgeCount: edges.length,
            exportTool: 'typescript.PHP.Sec.Scan (taint graph)'
        }
    };
}

/** Rang de chaque nœud = plus long chemin depuis une entrée (couche horizontale). */
function computeRanks(nodes: TaintNode[], edges: TaintEdge[]): Map<string, number> {
    const rank = new Map<string, number>();
    for (const node of nodes) {
        rank.set(node.id, 0);
    }
    // Relaxation itérative, bornée par le nombre de nœuds (protège des cycles).
    for (let iteration = 0; iteration < nodes.length; iteration++) {
        let changed = false;
        for (const edge of edges) {
            const candidate = (rank.get(edge.source) ?? 0) + 1;
            if (candidate > (rank.get(edge.target) ?? 0)) {
                rank.set(edge.target, candidate);
                changed = true;
            }
        }
        if (!changed) {
            break;
        }
    }
    return rank;
}

function escapeRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
