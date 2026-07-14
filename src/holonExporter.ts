import {
    DependencyModel,
    EntityKind,
    GraphDependency,
    GraphEntity,
    HolonEdge,
    HolonGeometry,
    HolonGraph,
    HolonNode,
    HolonStyling
} from './types';

const LEAF_W = 200;
const LEAF_H = 70;
const PAD = 24;
const HEADER = 40;
const GAP = 24;
const ROOT_GAP = 60;

const EXPORT_TOOL = 'typescript.PHP.Sec.Scan (AST dependency graph)';

interface Size {
    w: number;
    h: number;
}

const STYLING: Record<EntityKind, HolonStyling> = {
    file: {fill: '#e3f2fd', stroke: '#1976d2', strokeWidth: 2, opacity: 1},
    class: {fill: '#f3e5f5', stroke: '#7b1fa2', strokeWidth: 2, opacity: 1},
    function: {fill: '#e8f5e9', stroke: '#388e3c', strokeWidth: 2, opacity: 1},
    method: {fill: '#fff3e0', stroke: '#f57c00', strokeWidth: 2, opacity: 1},
    external: {fill: '#eceff1', stroke: '#90a4ae', strokeWidth: 1, opacity: 1}
};

const ARCHIMATE: Record<EntityKind, string> = {
    file: 'ApplicationComponent',
    class: 'ApplicationComponent',
    function: 'ApplicationFunction',
    method: 'ApplicationFunction',
    external: 'ApplicationService'
};

const RELATION: Record<GraphDependency['kind'], string> = {
    'call': 'Triggering',
    'method-call': 'Triggering',
    'static-call': 'Triggering',
    'instantiation': 'Association'
};

/**
 * Converts a {@link DependencyModel} into a Holon Architecture Modeler document.
 * A deterministic hierarchical layout assigns geometry so the output can be
 * opened directly in Holon without a manual arrange step.
 */
export class HolonExporter {
    private readonly childrenOf = new Map<string | null, GraphEntity[]>();
    private readonly geometry = new Map<string, HolonGeometry>();

    constructor(private readonly model: DependencyModel, private readonly exportedAt: string) {
        for (const entity of model.entities) {
            const bucket = this.childrenOf.get(entity.parentId) ?? [];
            bucket.push(entity);
            this.childrenOf.set(entity.parentId, bucket);
        }
    }

    export(): HolonGraph {
        this.layout();
        const nodes = this.model.entities.map(entity => this.toNode(entity));
        const edges = this.model.dependencies.map((dep, index) => this.toEdge(dep, index));
        return {
            version: '1.0',
            exportedAt: this.exportedAt,
            nodes,
            edges,
            metadata: {
                nodeCount: nodes.length,
                edgeCount: edges.length,
                exportTool: EXPORT_TOOL
            }
        };
    }

    // --- layout -----------------------------------------------------------

    private layout(): void {
        const roots = this.childrenOf.get(null) ?? [];
        let cursorX = PAD;
        for (const root of roots) {
            const size = this.measure(root);
            this.place(root, cursorX, PAD, size);
            cursorX += size.w + ROOT_GAP;
        }
    }

    private measure(entity: GraphEntity): Size {
        const children = this.childrenOf.get(entity.id) ?? [];
        if (children.length === 0) {
            return {w: LEAF_W, h: LEAF_H};
        }
        const childSizes = children.map(child => this.measure(child));
        const content = this.packSize(childSizes);
        return {
            w: content.w + 2 * PAD,
            h: content.h + HEADER + PAD
        };
    }

    private place(entity: GraphEntity, x: number, y: number, size: Size): void {
        this.geometry.set(entity.id, {x, y, w: size.w, h: size.h});
        const children = this.childrenOf.get(entity.id) ?? [];
        if (children.length === 0) {
            return;
        }
        const childSizes = children.map(child => this.measure(child));
        const positions = this.packPositions(childSizes);
        const originX = x + PAD;
        const originY = y + HEADER;
        children.forEach((child, i) => {
            this.place(child, originX + positions[i].x, originY + positions[i].y, childSizes[i]);
        });
    }

    /** Number of columns used to pack `count` children into a roughly square grid. */
    private columns(count: number): number {
        return Math.max(1, Math.ceil(Math.sqrt(count)));
    }

    private packPositions(sizes: Size[]): Array<{x: number; y: number}> {
        const cols = this.columns(sizes.length);
        const positions: Array<{x: number; y: number}> = [];
        let rowY = 0;
        for (let i = 0; i < sizes.length; i += cols) {
            const row = sizes.slice(i, i + cols);
            const rowHeight = Math.max(...row.map(s => s.h));
            let rowX = 0;
            for (const size of row) {
                positions.push({x: rowX, y: rowY});
                rowX += size.w + GAP;
            }
            rowY += rowHeight + GAP;
        }
        return positions;
    }

    private packSize(sizes: Size[]): Size {
        const cols = this.columns(sizes.length);
        let width = 0;
        let height = 0;
        for (let i = 0; i < sizes.length; i += cols) {
            const row = sizes.slice(i, i + cols);
            const rowWidth = row.reduce((sum, s) => sum + s.w, 0) + GAP * (row.length - 1);
            const rowHeight = Math.max(...row.map(s => s.h));
            width = Math.max(width, rowWidth);
            height += rowHeight + GAP;
        }
        return {w: width, h: Math.max(0, height - GAP)};
    }

    // --- mapping ----------------------------------------------------------

    private toNode(entity: GraphEntity): HolonNode {
        const hasChildren = (this.childrenOf.get(entity.id) ?? []).length > 0;
        const geometry = this.geometry.get(entity.id) ?? {x: 0, y: 0, w: LEAF_W, h: LEAF_H};
        return {
            id: entity.id,
            parentId: entity.parentId,
            type: hasChildren ? 'container' : 'node',
            geometry,
            styling: STYLING[entity.kind],
            data: {
                name: entity.name,
                archimateType: ARCHIMATE[entity.kind],
                documentation: this.documentation(entity)
            }
        };
    }

    private toEdge(dep: GraphDependency, index: number): HolonEdge {
        return {
            id: `edge-${index + 1}`,
            sourceId: dep.fromId,
            targetId: dep.toId,
            routing: 'straight',
            data: {
                relationType: RELATION[dep.kind],
                name: dep.name
            }
        };
    }

    private documentation(entity: GraphEntity): string {
        if (entity.external) {
            return `External / unresolved ${entity.kind === 'file' ? 'group' : entity.kind}.`;
        }
        return `${this.capitalize(entity.kind)} defined at ${entity.file}:${entity.line}.`;
    }

    private capitalize(text: string): string {
        return text.length === 0 ? text : text.charAt(0).toUpperCase() + text.slice(1);
    }
}

export function exportDependencyGraph(model: DependencyModel, exportedAt: string): HolonGraph {
    return new HolonExporter(model, exportedAt).export();
}
