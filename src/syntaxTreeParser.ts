import {CallArgument, CodeEvent, FunctionInfo, ModuleModel} from './types';

import {SyntaxNode, Tree} from "tree-sitter";

/** Constructions PHP dangereuses qui ne sont pas des `function_call_expression` mais agissent comme des sinks. */
const CONSTRUCT_SINKS: Record<string, string> = {
    echo_statement: 'echo',
    print_intrinsic: 'print',
    include_expression: 'include',
    include_once_expression: 'include_once',
    require_expression: 'require',
    require_once_expression: 'require_once'
};

export class SyntaxTreeParser {
    constructor(
        private sourceCode: Buffer,
        private tree: Tree,
        private filePath: string
    ) {
    }

    parse(): CodeEvent[] {
        const events: CodeEvent[] = [];
        this.traverseNode(this.tree.rootNode, events);
        return events;
    }

    /**
     * Analyse structurée : sépare les événements de premier niveau des corps de
     * fonctions/méthodes (avec leurs paramètres et retours), afin d'alimenter
     * l'analyse inter-procédurale.
     */
    parseModule(): ModuleModel {
        const module: ModuleModel = {file: this.filePath, topLevel: [], functions: []};
        this.walkModule(this.tree.rootNode, module, module.topLevel, null);
        return module;
    }

    private walkModule(node: SyntaxNode, module: ModuleModel, target: CodeEvent[], className: string | null): void {
        if (node.type === 'function_definition' || node.type === 'method_declaration') {
            const name = this.getFunctionName(node);
            const info: FunctionInfo = {
                name,
                qualifiedName: className ? `${className}::${name}` : name,
                params: this.extractParams(node),
                events: [],
                line: node.startPosition.row + 1,
                file: this.filePath,
                className
            };
            module.functions.push(info);
            const body = node.childForFieldName('body');
            if (body) {
                this.walkModule(body, module, info.events, className);
            }
            return;
        }

        if (node.type === 'class_declaration' || node.type === 'interface_declaration' || node.type === 'trait_declaration') {
            const name = this.getFunctionName(node);
            const list = node.childForFieldName('body');
            if (list) {
                for (const member of list.namedChildren) {
                    this.walkModule(member, module, target, name);
                }
            }
            return;
        }

        this.emitInto(node, target);
        for (const child of node.children) {
            this.walkModule(child, module, target, className);
        }
    }

    /** Émet, le cas échéant, l'événement associé à un nœud (affectation / appel / sink / retour). */
    private emitInto(node: SyntaxNode, target: CodeEvent[]): void {
        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');
            if (left?.type === 'variable_name' && right) {
                const details: CodeEvent['details'] = {
                    variable: this.getNodeText(left),
                    source: this.getNodeText(right)
                };
                if (right.type === 'function_call_expression') {
                    const argsNode = right.childForFieldName('arguments');
                    (details as any).callee = this.getFunctionName(right);
                    (details as any).calleeArgs = argsNode ? this.argumentsOf(argsNode) : [];
                }
                target.push({type: 'assignment', line: node.startPosition.row + 1, file: this.filePath, details});
            }
        } else if (node.type === 'function_call_expression') {
            const funcName = this.getFunctionName(node);
            const argsNode = node.childForFieldName('arguments');
            if (funcName && argsNode) {
                this.pushCall(node, funcName, this.argumentsOf(argsNode), target);
            }
        } else if (CONSTRUCT_SINKS[node.type]) {
            this.pushCall(node, CONSTRUCT_SINKS[node.type], [{text: this.getNodeText(node), variables: this.collectVariables(node)}], target);
        } else if (node.type === 'member_call_expression' || node.type === 'scoped_call_expression') {
            // Appels de méthode : `$this->m($x)`, `Foo::bar($x)` → nom de méthode + arguments.
            const nameNode = node.childForFieldName('name');
            const argsNode = node.childForFieldName('arguments');
            if (nameNode && argsNode) {
                this.pushCall(node, this.getNodeText(nameNode), this.argumentsOf(argsNode), target);
            }
        } else if (node.type === 'return_statement') {
            const expr = node.namedChildren[0];
            if (expr) {
                target.push({
                    type: 'return',
                    line: node.startPosition.row + 1,
                    file: this.filePath,
                    details: {variables: this.collectVariables(expr), text: this.getNodeText(expr)}
                });
            }
        }
    }

    /** Noms des paramètres d'une fonction/méthode, dans l'ordre. */
    private extractParams(node: SyntaxNode): string[] {
        const formal = node.namedChildren.find(c => c.type === 'formal_parameters');
        return formal ? this.collectVariables(formal) : [];
    }

    private getNodeText(node: SyntaxNode | null): string {
        if (!node) return '';
        return this.sourceCode.slice(node.startIndex, node.endIndex).toString('utf-8');
    }

    private getFunctionName(node: SyntaxNode): string {
        const funcNode = node.namedChildren.find(c => c.type === 'name');
        return funcNode ? this.getNodeText(funcNode) : '';
    }

    private traverseNode(node: SyntaxNode, events: CodeEvent[]): void {
        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');
            if (left?.type === 'variable_name' && right) {
                events.push({
                    type: 'assignment',
                    line: node.startPosition.row + 1,
                    file: this.filePath,
                    details: {
                        variable: this.getNodeText(left),
                        source: this.getNodeText(right)
                    }
                });
            }
        } else if (node.type === 'function_call_expression') {
            const funcName = this.getFunctionName(node);
            const argsNode = node.childForFieldName('arguments');
            if (funcName && argsNode) {
                this.pushCall(node, funcName, this.argumentsOf(argsNode), events);
            }
        } else if (CONSTRUCT_SINKS[node.type]) {
            // echo / print / include / require : l'ensemble de la construction est l'argument.
            const text = this.getNodeText(node);
            const variables = this.collectVariables(node);
            this.pushCall(node, CONSTRUCT_SINKS[node.type], [{text, variables}], events);
        }

        for (const child of node.children) {
            this.traverseNode(child, events);
        }
    }

    private pushCall(node: SyntaxNode, functionName: string, argumentExpressions: CallArgument[], events: CodeEvent[]): void {
        const flat: string[] = [];
        const seen = new Set<string>();
        for (const arg of argumentExpressions) {
            for (const variable of arg.variables) {
                if (!seen.has(variable)) {
                    seen.add(variable);
                    flat.push(variable);
                }
            }
        }
        if (flat.length === 0) {
            return;
        }
        events.push({
            type: 'function_call',
            line: node.startPosition.row + 1,
            file: this.filePath,
            details: {functionName, arguments: flat, argumentExpressions}
        });
    }

    /** Décompose un nœud `arguments` en une liste d'arguments (texte + variables). */
    private argumentsOf(argsNode: SyntaxNode): CallArgument[] {
        return argsNode.namedChildren.map(arg => ({
            text: this.getNodeText(arg),
            variables: this.collectVariables(arg)
        }));
    }

    /** Collecte, sans doublon, les noms de variables (`$x`) apparaissant sous un nœud, interpolations comprises. */
    private collectVariables(node: SyntaxNode): string[] {
        const names: string[] = [];
        const seen = new Set<string>();
        const visit = (current: SyntaxNode): void => {
            if (current.type === 'variable_name') {
                const name = this.getNodeText(current);
                if (!seen.has(name)) {
                    seen.add(name);
                    names.push(name);
                }
                return;
            }
            for (const child of current.namedChildren) {
                visit(child);
            }
        };
        visit(node);
        return names;
    }
}
