export interface Vulnerability {
    type: string;
    sink: string;
    variable?: string;
    line: number;
    file: string;
    trace: string;
    severity: 'error' | 'warning';
}

export interface SinkRule {
    /** Nom de la fonction ou construction dangereuse (ex. `mysqli_query`, `echo`). */
    name: string;
    /** Catégorie de vulnérabilité associée (ex. `sql_injection`, `xss`, `rce`). */
    type: string;
}

export interface Rules {
    sources: string[];
    /** Puits (sinks) où une donnée teintée devient une vulnérabilité. Défauts appliqués si omis. */
    sinks?: SinkRule[];
    /** Fonctions/casts qui désinfectent une donnée. Défauts appliqués si omis. */
    sanitizers?: string[];
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

export interface CallArgument {
    /** Texte source complet de l'argument (ex. `mysqli_real_escape_string($id)`). */
    text: string;
    /** Noms des variables (`$x`) présentes dans l'argument, interpolations comprises. */
    variables: string[];
}

export interface FunctionCallDetails {
    functionName: string;
    /** Liste aplatie des variables de tous les arguments (rétro-compatibilité). */
    arguments: string[];
    /** Détail par argument, permettant de détecter une désinfection intra-argument. */
    argumentExpressions?: CallArgument[];
}

export type TaintOrigin = 'source' | 'propagation' | 'sanitized';

export interface TaintFlowEntry {
    variable: string;
    source: string;
    line: number;
    action: 'assignment' | 'function_parameter';
    details: string;
    file: string;
    /** Pour une affectation : comment la variable a obtenu (ou perdu) sa teinte. */
    origin?: TaintOrigin;
    /** Pour un paramètre de fonction : true si l'appel constitue une vulnérabilité. */
    isVulnerable?: boolean;
    /** Pour un paramètre de fonction vulnérable : catégorie de la vulnérabilité. */
    vulnType?: string;
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
