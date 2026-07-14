import {SyntaxNode, Tree} from 'tree-sitter';
import {DependencyKind, DependencyModel, GraphDependency, GraphEntity} from './types';

interface PendingBody {
    ownerId: string;
    ownerClass: string | null;
    body: SyntaxNode;
    source: Buffer;
    file: string;
}

/**
 * Builds a project-wide dependency graph from PHP syntax trees.
 *
 * Definitions (files, classes, functions, methods) become entities; calls,
 * static calls, method calls and instantiations become dependencies. Symbols
 * are resolved across every file added to the builder, so cross-file
 * dependencies are captured. References to symbols that are never defined in
 * the analysed sources (PHP built-ins, third-party code, ...) are represented
 * as `external` entities so that no dependency ever dangles.
 */
export class DependencyGraphBuilder {
    private readonly entities = new Map<string, GraphEntity>();
    private readonly dependencies: GraphDependency[] = [];
    private readonly seenDeps = new Set<string>();

    private readonly funcByName = new Map<string, string>();
    private readonly classByName = new Map<string, string>();
    private readonly methodByQualified = new Map<string, string>();
    private readonly methodByName = new Map<string, string[]>();
    private readonly externalByKey = new Map<string, string>();

    private readonly pendingBodies: PendingBody[] = [];
    private externalContainerId: string | null = null;

    /** Register a parsed file. Collects its definitions; call resolution is deferred to {@link build}. */
    addFile(filePath: string, tree: Tree, source: Buffer): void {
        const fileId = this.entityId('file', filePath);
        this.addEntity({
            id: fileId,
            kind: 'file',
            name: this.baseName(filePath),
            parentId: null,
            line: 1,
            file: filePath,
            external: false
        });
        this.collect(tree.rootNode, source, filePath, fileId, null);
    }

    /** Resolve every deferred call site and return the finished model. */
    build(): DependencyModel {
        for (const pending of this.pendingBodies) {
            this.resolveBody(pending);
        }
        return {
            entities: Array.from(this.entities.values()),
            dependencies: this.dependencies
        };
    }

    // --- collection -------------------------------------------------------

    private collect(node: SyntaxNode, source: Buffer, file: string, fileId: string, classId: string | null): void {
        if (node.type === 'function_definition') {
            const name = this.childName(node, source);
            if (name) {
                const id = this.entityId('fn', name);
                this.addEntity({
                    id, kind: 'function', name, parentId: fileId,
                    line: node.startPosition.row + 1, file, external: false
                });
                this.funcByName.set(name, id);
                const body = node.childForFieldName('body');
                if (body) {
                    this.pendingBodies.push({ownerId: id, ownerClass: null, body, source, file});
                }
            }
            // Nested functions are uncommon; descend anyway so classes defined
            // inside conditionals are still discovered.
        } else if (node.type === 'class_declaration' || node.type === 'interface_declaration' || node.type === 'trait_declaration') {
            const name = this.childName(node, source);
            if (name) {
                const id = this.entityId('class', name);
                this.addEntity({
                    id, kind: 'class', name, parentId: fileId,
                    line: node.startPosition.row + 1, file, external: false
                });
                this.classByName.set(name, id);
                const list = node.childForFieldName('body');
                if (list) {
                    for (const member of list.namedChildren) {
                        this.collectMember(member, source, file, id, name);
                    }
                }
                return; // members handled explicitly above
            }
        }

        for (const child of node.namedChildren) {
            this.collect(child, source, file, fileId, classId);
        }
    }

    private collectMember(member: SyntaxNode, source: Buffer, file: string, classId: string, className: string): void {
        if (member.type !== 'method_declaration') {
            return;
        }
        const name = this.childName(member, source);
        if (!name) {
            return;
        }
        const id = this.entityId('method', `${className}::${name}`);
        this.addEntity({
            id, kind: 'method', name, parentId: classId,
            line: member.startPosition.row + 1, file, external: false
        });
        this.methodByQualified.set(`${className}::${name}`, id);
        const list = this.methodByName.get(name) ?? [];
        list.push(id);
        this.methodByName.set(name, list);

        const body = member.childForFieldName('body');
        if (body) {
            this.pendingBodies.push({ownerId: id, ownerClass: className, body, source, file});
        }
    }

    // --- resolution -------------------------------------------------------

    private resolveBody(pending: PendingBody): void {
        const {ownerId, ownerClass, body, source, file} = pending;
        this.walkCalls(body, source, callNode => {
            const line = callNode.startPosition.row + 1;
            switch (callNode.type) {
                case 'function_call_expression': {
                    const callee = this.childName(callNode, source);
                    if (callee) {
                        this.addDependency(ownerId, this.resolveFunction(callee, file), 'call', callee, line);
                    }
                    break;
                }
                case 'member_call_expression': {
                    const object = this.fieldText(callNode, 'object', source);
                    const method = this.fieldText(callNode, 'name', source);
                    if (method) {
                        this.addDependency(ownerId, this.resolveMethod(object, method, ownerClass, file), 'method-call', method, line);
                    }
                    break;
                }
                case 'scoped_call_expression': {
                    const scope = this.fieldText(callNode, 'scope', source);
                    const method = this.fieldText(callNode, 'name', source);
                    if (method) {
                        this.addDependency(ownerId, this.resolveStatic(scope, method, ownerClass, file), 'static-call', method, line);
                    }
                    break;
                }
                case 'object_creation_expression': {
                    const className = this.childName(callNode, source);
                    if (className) {
                        this.addDependency(ownerId, this.resolveClass(className, file), 'instantiation', className, line);
                    }
                    break;
                }
            }
        });
    }

    private resolveFunction(name: string, file: string): string {
        return this.funcByName.get(name) ?? this.external('fn', name, file);
    }

    private resolveClass(name: string, file: string): string {
        return this.classByName.get(name) ?? this.external('class', name, file);
    }

    private resolveMethod(object: string, method: string, ownerClass: string | null, file: string): string {
        if ((object === '$this' || object === 'self' || object === 'static') && ownerClass) {
            const own = this.methodByQualified.get(`${ownerClass}::${method}`);
            if (own) {
                return own;
            }
        }
        const candidates = this.methodByName.get(method);
        if (candidates && candidates.length === 1) {
            return candidates[0];
        }
        // Ambiguous or unknown receiver: cannot statically resolve the class.
        return this.external('method', method, file);
    }

    private resolveStatic(scope: string, method: string, ownerClass: string | null, file: string): string {
        const target = scope === 'self' || scope === 'static' || scope === 'parent' ? ownerClass : scope;
        if (target) {
            const qualified = this.methodByQualified.get(`${target}::${method}`);
            if (qualified) {
                return qualified;
            }
        }
        return this.external('method', `${target ?? '?'}::${method}`, file);
    }

    // --- helpers ----------------------------------------------------------

    private walkCalls(node: SyntaxNode, source: Buffer, visit: (call: SyntaxNode) => void): void {
        const CALL_TYPES = new Set([
            'function_call_expression',
            'member_call_expression',
            'scoped_call_expression',
            'object_creation_expression'
        ]);
        if (CALL_TYPES.has(node.type)) {
            visit(node);
        }
        for (const child of node.namedChildren) {
            this.walkCalls(child, source, visit);
        }
    }

    private addEntity(entity: GraphEntity): void {
        if (!this.entities.has(entity.id)) {
            this.entities.set(entity.id, entity);
        }
    }

    private addDependency(fromId: string, toId: string, kind: DependencyKind, name: string, line: number): void {
        if (fromId === toId) {
            return; // ignore direct self-recursion for a cleaner graph
        }
        const key = `${fromId}|${toId}|${kind}`;
        if (this.seenDeps.has(key)) {
            return;
        }
        this.seenDeps.add(key);
        this.dependencies.push({fromId, toId, kind, name, line});
    }

    private external(kind: 'fn' | 'class' | 'method', name: string, file: string): string {
        const key = `${kind}:${name}`;
        const existing = this.externalByKey.get(key);
        if (existing) {
            return existing;
        }
        const id = this.entityId('ext', key);
        this.externalByKey.set(key, id);
        this.addEntity({
            id,
            kind: 'external',
            name,
            parentId: this.ensureExternalContainer(),
            line: 0,
            file,
            external: true
        });
        return id;
    }

    private ensureExternalContainer(): string {
        if (this.externalContainerId === null) {
            this.externalContainerId = this.entityId('file', '<external>');
            this.addEntity({
                id: this.externalContainerId,
                kind: 'file',
                name: 'External dependencies',
                parentId: null,
                line: 0,
                file: '<external>',
                external: true
            });
        }
        return this.externalContainerId;
    }

    private childName(node: SyntaxNode, source: Buffer): string {
        const nameNode = node.childForFieldName('name') ?? node.namedChildren.find(c => c.type === 'name');
        return nameNode ? this.text(nameNode, source) : '';
    }

    private fieldText(node: SyntaxNode, field: string, source: Buffer): string {
        const child = node.childForFieldName(field);
        return child ? this.text(child, source) : '';
    }

    private text(node: SyntaxNode, source: Buffer): string {
        return source.slice(node.startIndex, node.endIndex).toString('utf-8');
    }

    private baseName(filePath: string): string {
        const parts = filePath.split(/[\\/]/);
        return parts[parts.length - 1] || filePath;
    }

    private entityId(prefix: string, key: string): string {
        return `${prefix}:${key}`;
    }
}
