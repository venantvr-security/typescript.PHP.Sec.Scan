import {CodeEvent} from './types';

import {SyntaxNode, Tree} from "tree-sitter";

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
                const varName = this.getNodeText(left);
                events.push({
                    type: 'assignment',
                    line: node.startPosition.row + 1,
                    file: this.filePath,
                    details: {
                        variable: varName,
                        source: this.getNodeText(right)
                    }
                });
            }
        } else if (node.type === 'expression_statement') {
            const callNodes = node.namedChildren.filter(c => c.type === 'function_call_expression');
            for (const callNode of callNodes) {
                const funcName = this.getFunctionName(callNode);
                const argsNode = callNode.childForFieldName('arguments');
                const argNames: string[] = [];
                if (argsNode && funcName) {
                    for (const arg of argsNode.namedChildren) {
                        const variableNode = arg.type === 'variable_name' ? arg : arg.namedChildren.find(c => c.type === 'variable_name');
                        if (variableNode && variableNode.type === 'variable_name') {
                            const argName = this.getNodeText(variableNode);
                            argNames.push(argName);
                        }
                        const encapsedString = arg.namedChildren.find(c => c.type === 'encapsed_string');
                        if (encapsedString) {
                            for (const child of encapsedString.namedChildren) {
                                if (child.type === 'variable_name') {
                                    const argName = this.getNodeText(child);
                                    argNames.push(argName);
                                }
                            }
                        }
                    }
                    if (argNames.length > 0) {
                        events.push({
                            type: 'function_call',
                            line: callNode.startPosition.row + 1,
                            file: this.filePath,
                            details: {
                                functionName: funcName,
                                arguments: argNames
                            }
                        });
                    }
                }
            }
        }

        for (const child of node.children) {
            this.traverseNode(child, events);
        }
    }
}