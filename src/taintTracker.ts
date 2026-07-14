import {AssignmentDetails, CodeEvent, FunctionCallDetails, Rules, TaintFlowEntry, Vulnerability} from './types';
import {TaintRuleSet} from './taintRules';

export class TaintAnalyzer {
    private taintedVars: Set<string> = new Set();
    private vulnerabilities: Vulnerability[] = [];
    private taintFlow: TaintFlowEntry[] = [];

    private readonly ruleSet: TaintRuleSet;

    constructor(
        private rules: Rules,
        private filePath: string
    ) {
        this.ruleSet = new TaintRuleSet(rules);
    }

    analyze(events: CodeEvent[]): Vulnerability[] {
        this.taintedVars.clear();
        this.vulnerabilities = [];
        this.taintFlow = [];

        for (const event of events) {
            if (event.type === 'assignment') {
                this.handleAssignment(event.line, event.details as AssignmentDetails);
            } else if (event.type === 'function_call') {
                this.handleCall(event.line, event.details as FunctionCallDetails);
            }
        }

        return this.vulnerabilities;
    }

    private handleAssignment(line: number, details: AssignmentDetails): void {
        const {variable, source} = details;

        // La désinfection prime : `$x = htmlspecialchars($tainted)` produit une valeur sûre.
        if (this.ruleSet.isSanitizedExpression(source)) {
            this.taintedVars.delete(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Désinfecté via ${source}`,
                file: this.filePath,
                origin: 'sanitized'
            });
            return;
        }

        if (this.ruleSet.isSource(source)) {
            this.taintedVars.add(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Assigné depuis la source ${source}`,
                file: this.filePath,
                origin: 'source'
            });
            this.reportUnsanitizedSource(variable, line, `Source non désinfectée: ${variable}`);
            return;
        }

        if (this.ruleSet.containsTaintedVar(source, this.taintedVars)) {
            this.taintedVars.add(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Propagé depuis une variable teintée (${source})`,
                file: this.filePath,
                origin: 'propagation'
            });
            this.reportUnsanitizedSource(variable, line, `Propagation de source non désinfectée: ${variable}`);
            return;
        }

        // Réaffectation à une valeur sûre : la variable n'est plus teintée.
        this.taintedVars.delete(variable);
    }

    private handleCall(line: number, details: FunctionCallDetails): void {
        const {functionName, arguments: args, argumentExpressions} = details;
        const sinkType = this.ruleSet.sinkType(functionName);

        // Chaque variable teintée est-elle désinfectée *dans son propre argument* ?
        // Ex. `mysqli_query(mysqli_real_escape_string($id))` : $id est protégé.
        const sanitizedInArg = this.ruleSet.sanitizedVariables(argumentExpressions);

        for (const arg of args) {
            if (!this.taintedVars.has(arg)) {
                continue;
            }
            const neutralised = sanitizedInArg.has(arg);
            const vulnerable = Boolean(sinkType) && !neutralised;

            this.taintFlow.push({
                variable: arg,
                source: arg,
                line,
                action: 'function_parameter',
                details: functionName,
                file: this.filePath,
                isVulnerable: vulnerable,
                vulnType: vulnerable ? sinkType! : undefined
            });

            if (vulnerable) {
                this.vulnerabilities.push({
                    type: sinkType!,
                    sink: functionName,
                    variable: arg,
                    line,
                    file: this.filePath,
                    trace: `Donnée teintée '${arg}' atteint le sink '${functionName}' (${sinkType})`,
                    severity: 'error'
                });
            }
        }
    }

    private reportUnsanitizedSource(variable: string, line: number, trace: string): void {
        this.vulnerabilities.push({
            type: 'unsanitized_source',
            sink: variable,
            variable,
            line,
            file: this.filePath,
            trace,
            severity: 'warning'
        });
    }

    /** Le journal de flux de teinte de la dernière analyse (affectations, propagations, sinks). */
    getTaintFlow(): TaintFlowEntry[] {
        return this.taintFlow;
    }

    printTaintFlow(): string {
        let output = '=== Taint Flow Report ===\n';
        if (this.taintFlow.length === 0) {
            output += 'No tainted variables detected.\n';
            return output;
        }

        for (const entry of this.taintFlow) {
            output += `\nFile: ${entry.file}\n`;
            output += `Line ${entry.line}: Variable '${entry.variable}' `;
            if (entry.action === 'assignment') {
                output += `assigned from source '${entry.source}'.\n`;
                output += `  Details: ${entry.details}\n`;
            } else if (entry.action === 'function_parameter') {
                output += `passed as parameter to function '${entry.details}'.\n`;
            }
        }
        output += '========================\n';
        return output;
    }
}
