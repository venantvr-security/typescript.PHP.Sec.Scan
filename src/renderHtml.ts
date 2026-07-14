import {HolonEdge, HolonGraph, HolonNode} from './types';

const MARGIN = 40;

interface Point {
    x: number;
    y: number;
}

interface EdgeStyle {
    color: string;
    dash: string;
    marker: string;
}

const EDGE_STYLE: Record<string, EdgeStyle> = {
    // Graphe de dépendances
    Triggering: {color: '#455a64', dash: '', marker: 'arrow-455a64'},
    Association: {color: '#7b1fa2', dash: '6 4', marker: 'arrow-7b1fa2'},
    // Graphe de teinte
    Flux: {color: '#f57c00', dash: '', marker: 'arrow-f57c00'},
    'Désinfection': {color: '#2e7d32', dash: '4 3', marker: 'arrow-2e7d32'},
    'Vulnérabilité': {color: '#c62828', dash: '', marker: 'arrow-c62828'},
    Usage: {color: '#9e9e9e', dash: '2 3', marker: 'arrow-9e9e9e'}
};

const DEFAULT_EDGE_STYLE: EdgeStyle = EDGE_STYLE.Triggering;

function edgeStyle(relationType: string): EdgeStyle {
    return EDGE_STYLE[relationType] ?? DEFAULT_EDGE_STYLE;
}

/** Génère un `<marker>` de flèche par couleur d'arête réellement utilisée. */
function renderMarkers(edgeTypes: Set<string>): string {
    const colors = new Set<string>();
    for (const type of edgeTypes) {
        colors.add(edgeStyle(type).color);
    }
    return Array.from(colors).map(color => {
        const id = `arrow-${color.replace('#', '')}`;
        return `    <marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="${color}"/>
    </marker>`;
    }).join('\n');
}

/**
 * Produit un document HTML autonome (SVG inline, sans dépendance externe)
 * prévisualisant un graphe Holon : les rectangles reprennent la géométrie et
 * le style des nœuds, les arêtes relient les nœuds avec une flèche et une
 * étiquette. Survoler un nœud affiche sa documentation.
 */
export function renderHolonGraphToHtml(graph: HolonGraph): string {
    const bounds = computeBounds(graph.nodes);
    const width = bounds.w + 2 * MARGIN;
    const height = bounds.h + 2 * MARGIN;
    const offsetX = MARGIN - bounds.x;
    const offsetY = MARGIN - bounds.y;

    const byId = new Map(graph.nodes.map(node => [node.id, node]));
    const ordered = orderByDepth(graph.nodes);

    const nodeSvg = ordered.map(node => renderNode(node, offsetX, offsetY)).join('\n');
    const edgeSvg = graph.edges
        .map(edge => renderEdge(edge, byId, offsetX, offsetY))
        .filter(Boolean)
        .join('\n');

    const legend = renderLegend(graph);
    const heading = graph.metadata.exportTool.includes('taint')
        ? 'Graphe de teinte (source → sink) — Holon Architecture Modeler'
        : graph.metadata.exportTool.includes('unified')
            ? 'Graphe unifié (dépendances + teinte) — Holon Architecture Modeler'
            : 'Graphe de dépendances — Holon Architecture Modeler';

    return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeXml(heading)}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #fafafa; color: #212121; }
  header { padding: 12px 20px; border-bottom: 1px solid #e0e0e0; background: #fff; position: sticky; top: 0; z-index: 1; }
  header h1 { font-size: 16px; margin: 0 0 4px; }
  header .meta { font-size: 12px; color: #616161; }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 8px; font-size: 12px; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .legend i { width: 14px; height: 14px; border-radius: 3px; display: inline-block; border: 1px solid rgba(0,0,0,.25); }
  .canvas { overflow: auto; padding: 20px; }
  .node-label { font-size: 13px; font-weight: 600; fill: #212121; }
  .node-sub { font-size: 10px; fill: #616161; }
  .edge-label { font-size: 10px; fill: #37474f; }
  svg text { pointer-events: none; }
  @media (prefers-color-scheme: dark) {
    body { background: #121212; color: #e0e0e0; }
    header { background: #1e1e1e; border-color: #333; }
    header .meta, .node-sub, .edge-label { fill: #b0b0b0; color: #b0b0b0; }
    .node-label { fill: #f5f5f5; }
    .canvas { filter: none; }
  }
</style>
</head>
<body>
<header>
  <h1>${escapeXml(heading)}</h1>
  <div class="meta">${graph.metadata.nodeCount} nœuds · ${graph.metadata.edgeCount} arêtes · exporté le ${escapeXml(graph.exportedAt)} · ${escapeXml(graph.metadata.exportTool)}</div>
  <div class="legend">${legend}</div>
</header>
<div class="canvas">
<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
${renderMarkers(new Set(graph.edges.map(e => e.data.relationType)))}
  </defs>
  <g class="nodes">
${nodeSvg}
  </g>
  <g class="edges">
${edgeSvg}
  </g>
</svg>
</div>
</body>
</html>
`;
}

function renderNode(node: HolonNode, offsetX: number, offsetY: number): string {
    const {x, y, w, h} = node.geometry;
    const px = x + offsetX;
    const py = y + offsetY;
    const {fill, stroke, strokeWidth, opacity} = node.styling;
    const isContainer = node.type === 'container';
    // Étiquette en haut pour les conteneurs (le corps accueille les enfants), centrée pour les feuilles.
    const labelY = isContainer ? py + 20 : py + h / 2 - 2;
    const subY = isContainer ? py + 34 : py + h / 2 + 14;
    return `    <g>
      <title>${escapeXml(node.data.name)} — ${escapeXml(node.data.archimateType)}\n${escapeXml(node.data.documentation)}</title>
      <rect x="${px}" y="${py}" width="${w}" height="${h}" rx="8" ry="8" fill="${fill}" fill-opacity="${opacity}" stroke="${stroke}" stroke-width="${strokeWidth}"/>
      <text class="node-label" x="${px + w / 2}" y="${labelY}" text-anchor="middle">${escapeXml(truncate(node.data.name, w))}</text>
      <text class="node-sub" x="${px + w / 2}" y="${subY}" text-anchor="middle">${escapeXml(node.data.archimateType)}</text>
    </g>`;
}

function renderEdge(edge: HolonEdge, byId: Map<string, HolonNode>, offsetX: number, offsetY: number): string {
    const source = byId.get(edge.sourceId);
    const target = byId.get(edge.targetId);
    if (!source || !target) {
        return '';
    }
    const sc = center(source, offsetX, offsetY);
    const tc = center(target, offsetX, offsetY);
    const start = borderPoint(source, offsetX, offsetY, tc);
    const end = borderPoint(target, offsetX, offsetY, sc);
    const style = edgeStyle(edge.data.relationType);
    const mid = {x: (start.x + end.x) / 2, y: (start.y + end.y) / 2};
    const label = edge.data.name
        ? `    <text class="edge-label" x="${mid.x}" y="${mid.y - 3}" text-anchor="middle">${escapeXml(truncate(edge.data.name, 120))}</text>`
        : '';
    const dash = style.dash ? ` stroke-dasharray="${style.dash}"` : '';
    return `    <line x1="${start.x}" y1="${start.y}" x2="${end.x}" y2="${end.y}" stroke="${style.color}" stroke-width="1.5" stroke-opacity="0.75"${dash} marker-end="url(#${style.marker})"/>
${label}`;
}

function renderLegend(graph: HolonGraph): string {
    const seen = new Map<string, string>();
    for (const node of graph.nodes) {
        if (!seen.has(node.data.archimateType)) {
            seen.set(node.data.archimateType, node.styling.fill);
        }
    }
    const items = Array.from(seen.entries())
        .map(([type, fill]) => `<span><i style="background:${fill}"></i>${escapeXml(type)}</span>`);

    const edgeTypes = new Set(graph.edges.map(e => e.data.relationType));
    for (const type of edgeTypes) {
        const color = edgeStyle(type).color;
        items.push(`<span><i style="background:${color};border-radius:2px"></i>${escapeXml(type)}</span>`);
    }
    return items.join('');
}

// --- géométrie ------------------------------------------------------------

function computeBounds(nodes: HolonNode[]): {x: number; y: number; w: number; h: number} {
    if (nodes.length === 0) {
        return {x: 0, y: 0, w: 200, h: 200};
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const node of nodes) {
        const {x, y, w, h} = node.geometry;
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x + w);
        maxY = Math.max(maxY, y + h);
    }
    return {x: minX, y: minY, w: maxX - minX, h: maxY - minY};
}

function center(node: HolonNode, offsetX: number, offsetY: number): Point {
    return {
        x: node.geometry.x + offsetX + node.geometry.w / 2,
        y: node.geometry.y + offsetY + node.geometry.h / 2
    };
}

/** Point où le segment [centre du nœud → cible] coupe le bord du rectangle du nœud. */
function borderPoint(node: HolonNode, offsetX: number, offsetY: number, toward: Point): Point {
    const c = center(node, offsetX, offsetY);
    const halfW = node.geometry.w / 2;
    const halfH = node.geometry.h / 2;
    const dx = toward.x - c.x;
    const dy = toward.y - c.y;
    if (dx === 0 && dy === 0) {
        return c;
    }
    const scale = 1 / Math.max(Math.abs(dx) / halfW, Math.abs(dy) / halfH);
    return {x: c.x + dx * scale, y: c.y + dy * scale};
}

/** Ordonne les nœuds par profondeur croissante pour que les conteneurs soient dessinés avant leurs enfants. */
function orderByDepth(nodes: HolonNode[]): HolonNode[] {
    const byId = new Map(nodes.map(n => [n.id, n]));
    const depthOf = (node: HolonNode): number => {
        let depth = 0;
        let current: HolonNode | undefined = node;
        while (current && current.parentId !== null) {
            depth++;
            current = byId.get(current.parentId);
        }
        return depth;
    };
    return [...nodes].sort((a, b) => depthOf(a) - depthOf(b));
}

// --- utilitaires ----------------------------------------------------------

function truncate(text: string, widthPx: number): string {
    const maxChars = Math.max(4, Math.floor(widthPx / 8));
    return text.length > maxChars ? text.slice(0, maxChars - 1) + '…' : text;
}

function escapeXml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
