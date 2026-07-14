import {AssignmentDetails, CodeEvent, FunctionCallDetails, Rules, TaintFlowEntry, Vulnerability} from './types';

export class TaintAnalyzer {
    private taintedVars: Set<string> = new Set();
    private vulnerabilities: Vulnerability[] = [];
    private taintFlow: TaintFlowEntry[] = [];

    constructor(
        private rules: Rules,
        private filePath: string
    ) {
    }

    analyze(events: CodeEvent[]): Vulnerability[] {
        this.taintedVars.clear();
        this.vulnerabilities = [];
        this.taintFlow = [];

        for (const event of events) {
            if (event.type === 'assignment') {
                const {variable, source} = event.details as AssignmentDetails;
                console.log(`Analyzing assignment: ${variable} = ${source}`);
                if (this.isSource(source)) {
                    this.taintedVars.add(variable);
                    console.log(`Adding unsanitized_source for: ${variable}`);
                    this.taintFlow.push({
                        variable,
                        source,
                        line: event.line,
                        action: 'assignment',
                        details: `Assigned from ${source}`,
                        file: this.filePath
                    });
                    if (this.isVulnerability()) {
                        this.vulnerabilities.push({
                            type: 'unsanitized_source',
                            sink: variable,
                            variable,
                            line: event.line,
                            file: this.filePath,
                            trace: `Source non désinfectée: ${variable}`,
                            severity: 'warning'
                        });
                    }
                } else if (this.taintedVars.has(source)) {
                    this.taintedVars.add(variable);
                    console.log(`Adding unsanitized_source (propagation) for: ${variable}`);
                    this.taintFlow.push({
                        variable,
                        source,
                        line: event.line,
                        action: 'assignment',
                        details: `Propagated from tainted variable ${source}`,
                        file: this.filePath
                    });
                    if (this.isVulnerability()) {
                        this.vulnerabilities.push({
                            type: 'unsanitized_source',
                            sink: variable,
                            variable,
                            line: event.line,
                            file: this.filePath,
                            trace: `Propagation de source non désinfectée: ${variable}`,
                            severity: 'warning'
                        });
                    }
                }
            } else if (event.type === 'function_call') {
                const {functionName, arguments: args} = event.details as FunctionCallDetails;
                for (const arg of args) {
                    if (this.taintedVars.has(arg)) {
                        console.log(`Tracking tainted variable in function call: ${arg}`);
                        this.taintFlow.push({
                            variable: arg,
                            source: arg,
                            line: event.line,
                            action: 'function_parameter',
                            details: functionName,
                            file: this.filePath
                        });
                    }
                }
            }
        }

        return this.vulnerabilities;
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
        console.log(`Checking if source: ${text}`);
        // Un accès à une superglobale peut être direct (`$_POST`) ou indexé
        // (`$_POST['id']`, `$_GET["x"]['y']`). On considère la source détectée
        // dès que le texte correspond exactement à une source configurée ou
        // commence par cette source suivie d'un accès par index.
        return this.rules.sources.some(
            source => text === source || text.startsWith(`${source}[`)
        );
    }

    private isVulnerability(): boolean { // à déplacer...
        return true;
    }
}
