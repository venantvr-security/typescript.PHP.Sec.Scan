import {
    AssignmentDetails,
    CodeEvent,
    FunctionCallDetails,
    FunctionInfo,
    ModuleModel,
    ReturnDetails,
    Rules,
    TaintFlowEntry,
    Vulnerability
} from './types';
import {TaintRuleSet} from './taintRules';

const GLOBAL = '<global>';

interface FunctionSummary {
    returnsTainted: boolean;
}

export interface InterproceduralResult {
    vulnerabilities: Vulnerability[];
    flow: TaintFlowEntry[];
}

/**
 * Analyse de teinte **inter-procédurale**. Le suivi traverse les appels de
 * fonctions et méthodes définies dans le projet : les arguments teintés
 * teintent les paramètres correspondants (les paramètres deviennent des
 * relais), les sinks atteints à l'intérieur d'un appelé sont signalés avec la
 * chaîne d'appel, et la teinte du retour se propage à l'appelant.
 *
 * La récursion est bornée par un garde de cycle et les résumés de fonctions
 * sont mémoïsés par (fonction, ensemble de paramètres teintés).
 */
export class InterproceduralAnalyzer {
    private readonly rules: TaintRuleSet;
    private readonly functions = new Map<string, FunctionInfo>();
    private readonly vulnerabilities: Vulnerability[] = [];
    private readonly flow: TaintFlowEntry[] = [];
    private readonly vulnKeys = new Set<string>();
    private readonly summaries = new Map<string, FunctionSummary>();
    private readonly onStack = new Set<string>();

    constructor(rules: Rules) {
        this.rules = new TaintRuleSet(rules);
    }

    analyze(modules: ModuleModel[]): InterproceduralResult {
        for (const module of modules) {
            for (const fn of module.functions) {
                if (!this.functions.has(fn.name)) {
                    this.functions.set(fn.name, fn);
                }
                this.functions.set(fn.qualifiedName, fn);
            }
        }

        // Contexte global de chaque fichier.
        for (const module of modules) {
            this.runFrame(module.topLevel, new Set(), GLOBAL, module.file, [GLOBAL]);
        }

        // Chaque fonction est aussi analysée isolément (sources internes), paramètres non teintés.
        for (const module of modules) {
            for (const fn of module.functions) {
                this.runFrame(fn.events, new Set(), fn.qualifiedName, fn.file, [GLOBAL, fn.qualifiedName]);
            }
        }

        return {vulnerabilities: this.vulnerabilities, flow: this.flow};
    }

    private runFrame(events: CodeEvent[], tainted: Set<string>, scope: string, file: string, chain: string[]): FunctionSummary {
        let returnsTainted = false;
        for (const event of events) {
            if (event.type === 'assignment') {
                this.handleAssignment(event, tainted, scope, file, chain);
            } else if (event.type === 'function_call') {
                this.handleCall(event, tainted, scope, file, chain);
            } else if (event.type === 'return') {
                const details = event.details as ReturnDetails;
                if (!this.rules.isSanitizedExpression(details.text) && this.rules.containsTaintedVar(details.text, tainted)) {
                    returnsTainted = true;
                }
            }
        }
        return {returnsTainted};
    }

    private handleAssignment(event: CodeEvent, tainted: Set<string>, scope: string, file: string, chain: string[]): void {
        const details = event.details as AssignmentDetails;
        const {variable, source, callee, calleeArgs} = details;

        if (this.rules.isSanitizedExpression(source)) {
            tainted.delete(variable);
            this.pushFlow({variable, source, line: event.line, action: 'assignment', details: `Désinfecté via ${source}`, file, scope, origin: 'sanitized'});
            return;
        }

        if (this.rules.isSource(source)) {
            tainted.add(variable);
            this.pushFlow({variable, source, line: event.line, action: 'assignment', details: `Source ${source}`, file, scope, origin: 'source'});
            this.reportWarning(variable, event.line, file, scope, `Source non désinfectée: ${variable}`);
            return;
        }

        // Membre droit = appel à une fonction définie : la teinte du résultat dépend de son retour.
        if (callee && this.functions.has(callee)) {
            const taintedArgs = this.taintedArguments(calleeArgs, tainted);
            const returnsTainted = taintedArgs.length > 0
                && this.invoke(callee, taintedArgs, scope, file, event.line, chain).returnsTainted;
            if (returnsTainted) {
                tainted.add(variable);
                this.pushFlow({variable, source, line: event.line, action: 'assignment', details: `Retour teinté de ${callee}()`, file, scope, origin: 'propagation'});
                this.reportWarning(variable, event.line, file, scope, `Propagation via le retour de ${callee}()`);
            } else {
                tainted.delete(variable);
            }
            return;
        }

        if (this.rules.containsTaintedVar(source, tainted)) {
            tainted.add(variable);
            this.pushFlow({variable, source, line: event.line, action: 'assignment', details: `Propagé depuis ${source}`, file, scope, origin: 'propagation'});
            this.reportWarning(variable, event.line, file, scope, `Propagation de source non désinfectée: ${variable}`);
            return;
        }

        tainted.delete(variable);
    }

    private handleCall(event: CodeEvent, tainted: Set<string>, scope: string, file: string, chain: string[]): void {
        const details = event.details as FunctionCallDetails;
        const {functionName, arguments: args, argumentExpressions} = details;

        // Appel à une fonction/méthode définie : propagation inter-procédurale.
        if (this.functions.has(functionName)) {
            const taintedArgs = this.taintedArguments(argumentExpressions, tainted);
            if (taintedArgs.length > 0) {
                this.invoke(functionName, taintedArgs, scope, file, event.line, chain);
            }
            return;
        }

        // Sinon : fonction/construction native → détection de sink classique.
        const sinkType = this.rules.sinkType(functionName);
        const sanitizedInArg = this.rules.sanitizedVariables(argumentExpressions);
        for (const arg of args) {
            if (!tainted.has(arg)) {
                continue;
            }
            const vulnerable = Boolean(sinkType) && !sanitizedInArg.has(arg);
            this.pushFlow({
                variable: arg, source: arg, line: event.line, action: 'function_parameter',
                details: functionName, file, scope, isVulnerable: vulnerable, vulnType: vulnerable ? sinkType! : undefined
            });
            if (vulnerable) {
                this.reportVulnerability(sinkType!, functionName, arg, event.line, file, scope, chain);
            }
        }
    }

    /** Positions (et variables) des arguments qui transportent une teinte non désinfectée. */
    private taintedArguments(argExprs: FunctionCallDetails['argumentExpressions'] | undefined, tainted: Set<string>): Array<{position: number; variables: string[]}> {
        const result: Array<{position: number; variables: string[]}> = [];
        (argExprs ?? []).forEach((arg, position) => {
            if (this.rules.isSanitizedExpression(arg.text)) {
                return;
            }
            const taintedVars = arg.variables.filter(v => tainted.has(v));
            if (taintedVars.length > 0) {
                result.push({position, variables: taintedVars});
            }
        });
        return result;
    }

    /** Entre dans une fonction appelée : lie les paramètres, analyse le corps, renvoie le résumé. */
    private invoke(
        name: string,
        taintedArgs: Array<{position: number; variables: string[]}>,
        callerScope: string,
        file: string,
        line: number,
        chain: string[]
    ): FunctionSummary {
        const fn = this.functions.get(name)!;
        const taintedParams = new Set<string>();
        for (const {position, variables} of taintedArgs) {
            const param = fn.params[position];
            if (!param) {
                continue;
            }
            taintedParams.add(param);
            // Arête de liaison : argument de l'appelant → paramètre de l'appelé.
            for (const argVar of variables) {
                this.pushFlow({
                    variable: argVar, source: argVar, line, action: 'parameter_binding',
                    details: param, file, scope: callerScope, targetScope: fn.qualifiedName
                });
            }
        }

        if (taintedParams.size === 0) {
            return {returnsTainted: false};
        }

        const key = `${fn.qualifiedName}|${Array.from(taintedParams).sort().join(',')}`;
        if (this.onStack.has(key)) {
            return this.summaries.get(key) ?? {returnsTainted: false}; // garde de cycle
        }
        const cached = this.summaries.get(key);
        if (cached) {
            return cached;
        }

        this.onStack.add(key);
        const summary = this.runFrame(fn.events, new Set(taintedParams), fn.qualifiedName, fn.file, [...chain, fn.qualifiedName]);
        this.onStack.delete(key);
        this.summaries.set(key, summary);
        return summary;
    }

    private reportVulnerability(type: string, sink: string, variable: string, line: number, file: string, scope: string, chain: string[]): void {
        const key = `${file}:${line}:${type}:${sink}:${variable}:${scope}`;
        if (this.vulnKeys.has(key)) {
            return;
        }
        this.vulnKeys.add(key);
        const path = chain.join(' → ');
        this.vulnerabilities.push({
            type, sink, variable, line, file,
            trace: `Donnée teintée '${variable}' atteint le sink '${sink}' (${type}) — chemin: ${path}`,
            severity: 'error',
            scope
        });
    }

    private reportWarning(variable: string, line: number, file: string, scope: string, trace: string): void {
        const key = `${file}:${line}:unsanitized_source:${variable}:${scope}`;
        if (this.vulnKeys.has(key)) {
            return;
        }
        this.vulnKeys.add(key);
        this.vulnerabilities.push({type: 'unsanitized_source', sink: variable, variable, line, file, trace, severity: 'warning'});
    }

    private pushFlow(entry: TaintFlowEntry): void {
        this.flow.push(entry);
    }
}
