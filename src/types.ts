export interface Vulnerability {
    type: string;
    sink: string;
    variable?: string;
    line: number;
    file: string;
    trace: string;
    severity: 'error' | 'warning';
}

export interface Rules {
    sources: string[];
}

export interface CodeEvent {
    type: 'assignment' | 'function_call';
    line: number;
    file: string;
    details: AssignmentDetails | FunctionCallDetails;
}

export interface AssignmentDetails {
    variable: string;
    source: string;
}

export interface FunctionCallDetails {
    functionName: string;
    arguments: string[];
}

export interface TaintFlowEntry {
    variable: string;
    source: string;
    line: number;
    action: 'assignment' | 'function_parameter';
    details: string;
    file: string;
}

// ---------------------------------------------------------------------------
// Dependency graph — intermediate model produced from the AST
// ---------------------------------------------------------------------------

export type EntityKind = 'file' | 'class' | 'function' | 'method' | 'external';

export interface GraphEntity {
    id: string;
    kind: EntityKind;
    name: string;
    parentId: string | null;
    line: number;
    file: string;
    /** True when the entity is referenced but not defined in the analysed sources. */
    external: boolean;
}

export type DependencyKind = 'call' | 'method-call' | 'static-call' | 'instantiation';

export interface GraphDependency {
    fromId: string;
    toId: string;
    kind: DependencyKind;
    name: string;
    line: number;
}

export interface DependencyModel {
    entities: GraphEntity[];
    dependencies: GraphDependency[];
}

// ---------------------------------------------------------------------------
// Holon export format (compatible with the Holon Architecture Modeler)
// ---------------------------------------------------------------------------

export interface HolonGeometry {
    x: number;
    y: number;
    w: number;
    h: number;
}

export interface HolonStyling {
    fill: string;
    stroke: string;
    strokeWidth: number;
    opacity: number;
}

export interface HolonNodeData {
    name: string;
    archimateType: string;
    documentation: string;
}

export interface HolonNode {
    id: string;
    parentId: string | null;
    type: 'container' | 'node';
    geometry: HolonGeometry;
    styling: HolonStyling;
    data: HolonNodeData;
}

export interface HolonEdgeData {
    relationType: string;
    name: string;
}

export interface HolonEdge {
    id: string;
    sourceId: string;
    targetId: string;
    routing: 'straight';
    data: HolonEdgeData;
}

export interface HolonMetadata {
    nodeCount: number;
    edgeCount: number;
    exportTool: string;
}

export interface HolonGraph {
    version: string;
    exportedAt: string;
    nodes: HolonNode[];
    edges: HolonEdge[];
    metadata: HolonMetadata;
}
