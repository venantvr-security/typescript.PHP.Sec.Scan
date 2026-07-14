import {CodeEvent} from './types';

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
                this.pushCall(node, funcName, this.collectVariables(argsNode), events);
            }
        } else if (CONSTRUCT_SINKS[node.type]) {
            // echo / print / include / require : variables utilisées directement.
            this.pushCall(node, CONSTRUCT_SINKS[node.type], this.collectVariables(node), events);
        }

        for (const child of node.children) {
            this.traverseNode(child, events);
        }
    }

    private pushCall(node: SyntaxNode, functionName: string, args: string[], events: CodeEvent[]): void {
        if (args.length === 0) {
            return;
        }
        events.push({
            type: 'function_call',
            line: node.startPosition.row + 1,
            file: this.filePath,
            details: {functionName, arguments: args}
        });
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
