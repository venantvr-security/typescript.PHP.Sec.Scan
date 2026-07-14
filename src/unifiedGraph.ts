import {HolonEdge, HolonGraph, HolonNode, HolonStyling, TaintFlowEntry, Vulnerability} from './types';

const GLOBAL = '<global>';

const VULN_STYLING: HolonStyling = {fill: '#ffcdd2', stroke: '#c62828', strokeWidth: 2, opacity: 1};

/**
 * Vue **unifiée** : la structure du graphe de dépendances (fichiers, classes,
 * fonctions, méthodes) enrichie d'une surcouche de teinte.
 *
 * - Les nœuds dont la portée atteint un sink avec une donnée teintée sont
 *   colorés en rouge (« vulnérable »).
 * - Les arêtes d'appel qui transportent une donnée teintée sont mises en
 *   évidence en orange (relation `Flux`), qu'elles existent déjà dans le
 *   graphe de dépendances ou qu'il faille les ajouter.
 *
 * @param dependencyGraph graphe de dépendances déjà exporté (avec géométrie).
 * @param vulnerabilities vulnérabilités inter-procédurales (avec `scope`).
 * @param flow             journal de flux inter-procédural (liaisons de paramètres).
 */
export function exportUnifiedGraph(
    dependencyGraph: HolonGraph,
    vulnerabilities: Vulnerability[],
    flow: TaintFlowEntry[]
): HolonGraph {
    const nodeIds = new Set(dependencyGraph.nodes.map(n => n.id));

    // Portées vulnérables → identifiants de nœuds du graphe de dépendances.
    const vulnerableNodes = new Map<string, string[]>(); // nodeId -> catégories
    for (const vuln of vulnerabilities) {
        if (vuln.severity !== 'error' || !vuln.scope) {
            continue;
        }
        const id = scopeToNodeId(vuln.scope, vuln.file);
        if (nodeIds.has(id)) {
            const list = vulnerableNodes.get(id) ?? [];
            if (!list.includes(vuln.type)) {
                list.push(vuln.type);
            }
            vulnerableNodes.set(id, list);
        }
    }

    // Paires d'appel (appelant → appelé) qui transportent une teinte.
    const taintPairs = new Set<string>();
    for (const entry of flow) {
        if (entry.action !== 'parameter_binding' || !entry.targetScope) {
            continue;
        }
        const from = scopeToNodeId(entry.scope ?? GLOBAL, entry.file);
        const to = scopeToNodeId(entry.targetScope, entry.file);
        if (nodeIds.has(from) && nodeIds.has(to)) {
            taintPairs.add(`${from}|${to}`);
        }
    }

    const nodes: HolonNode[] = dependencyGraph.nodes.map(node => {
        const categories = vulnerableNodes.get(node.id);
        if (!categories) {
            return node;
        }
        return {
            ...node,
            styling: VULN_STYLING,
            data: {
                ...node.data,
                documentation: `⚠ Vulnérable (${categories.join(', ')}). ${node.data.documentation}`
            }
        };
    });

    // Recolore les arêtes de dépendance porteuses de teinte ; ajoute celles qui manquent.
    const matched = new Set<string>();
    const edges: HolonEdge[] = dependencyGraph.edges.map(edge => {
        const key = `${edge.sourceId}|${edge.targetId}`;
        if (taintPairs.has(key)) {
            matched.add(key);
            return {...edge, data: {relationType: 'Flux', name: taintLabel(edge.data.name)}};
        }
        return edge;
    });

    let extra = 0;
    for (const pair of taintPairs) {
        if (matched.has(pair)) {
            continue;
        }
        const [sourceId, targetId] = pair.split('|');
        edges.push({
            id: `taint-${++extra}`,
            sourceId,
            targetId,
            routing: 'straight',
            data: {relationType: 'Flux', name: 'teinte'}
        });
    }

    return {
        version: '1.0',
        exportedAt: dependencyGraph.exportedAt,
        nodes,
        edges,
        metadata: {
            nodeCount: nodes.length,
            edgeCount: edges.length,
            exportTool: 'typescript.PHP.Sec.Scan (unified graph)'
        }
    };
}

function scopeToNodeId(scope: string, file: string): string {
    if (scope === GLOBAL) {
        return `file:${file}`;
    }
    if (scope.includes('::')) {
        return `method:${scope}`;
    }
    return `fn:${scope}`;
}

function taintLabel(name: string): string {
    return name ? `${name} · teinte` : 'teinte';
}
