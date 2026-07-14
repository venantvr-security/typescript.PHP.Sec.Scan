import {AssignmentDetails, CodeEvent, FunctionCallDetails, Rules, TaintFlowEntry, Vulnerability} from './types';
import {DEFAULT_SANITIZERS, DEFAULT_SINKS} from './defaultRules';

export class TaintAnalyzer {
    private taintedVars: Set<string> = new Set();
    private vulnerabilities: Vulnerability[] = [];
    private taintFlow: TaintFlowEntry[] = [];

    private readonly sinkTypes: Map<string, string>;
    private readonly sanitizers: string[];

    constructor(
        private rules: Rules,
        private filePath: string
    ) {
        this.sinkTypes = new Map((rules.sinks ?? DEFAULT_SINKS).map(sink => [sink.name, sink.type]));
        this.sanitizers = rules.sanitizers ?? DEFAULT_SANITIZERS;
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
        if (this.isSanitizedExpression(source)) {
            this.taintedVars.delete(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Désinfecté via ${source}`,
                file: this.filePath
            });
            return;
        }

        if (this.isSource(source)) {
            this.taintedVars.add(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Assigné depuis la source ${source}`,
                file: this.filePath
            });
            this.reportUnsanitizedSource(variable, line, `Source non désinfectée: ${variable}`);
            return;
        }

        if (this.containsTaintedVar(source)) {
            this.taintedVars.add(variable);
            this.taintFlow.push({
                variable, source, line,
                action: 'assignment',
                details: `Propagé depuis une variable teintée (${source})`,
                file: this.filePath
            });
            this.reportUnsanitizedSource(variable, line, `Propagation de source non désinfectée: ${variable}`);
            return;
        }

        // Réaffectation à une valeur sûre : la variable n'est plus teintée.
        this.taintedVars.delete(variable);
    }

    private handleCall(line: number, details: FunctionCallDetails): void {
        const {functionName, arguments: args} = details;
        const sinkType = this.sinkType(functionName);

        for (const arg of args) {
            if (!this.taintedVars.has(arg)) {
                continue;
            }
            this.taintFlow.push({
                variable: arg,
                source: arg,
                line,
                action: 'function_parameter',
                details: functionName,
                file: this.filePath
            });

            if (sinkType) {
                this.vulnerabilities.push({
                    type: sinkType,
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

    private isSource(text: string): boolean {
        // Un accès à une superglobale peut être direct (`$_POST`) ou indexé
        // (`$_POST['id']`, `$_GET["x"]['y']`). On considère la source détectée
        // dès que le texte correspond exactement à une source configurée ou
        // commence par cette source suivie d'un accès par index.
        return this.rules.sources.some(
            source => text === source || text.startsWith(`${source}[`)
        );
    }

    /** Le sink correspondant à un nom de fonction/construction, ou `null` si ce n'en est pas un. */
    private sinkType(functionName: string): string | null {
        return this.sinkTypes.get(functionName) ?? null;
    }

    /** Vrai si l'expression applique un désinfectant (appel `sanitizer(...)` ou cast `(int)`, ...). */
    private isSanitizedExpression(source: string): boolean {
        return this.sanitizers.some(sanitizer => {
            if (sanitizer.startsWith('(')) {
                return source.includes(sanitizer); // cast, ex. (int)
            }
            return new RegExp(`(^|[^A-Za-z0-9_$])${this.escapeRegExp(sanitizer)}\\s*\\(`).test(source);
        });
    }

    /** Vrai si l'expression référence une variable actuellement teintée (comme jeton entier). */
    private containsTaintedVar(source: string): boolean {
        for (const tainted of this.taintedVars) {
            if (new RegExp(`${this.escapeRegExp(tainted)}(?![A-Za-z0-9_])`).test(source)) {
                return true;
            }
        }
        return false;
    }

    private escapeRegExp(text: string): string {
        return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}
