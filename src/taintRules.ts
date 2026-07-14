import {CallArgument, Rules} from './types';
import {DEFAULT_SANITIZERS, DEFAULT_SINKS} from './defaultRules';

/**
 * Décisions élémentaires de l'analyse de teinte (source / sink / désinfectant),
 * partagées entre l'analyse intra-procédurale ({@link TaintAnalyzer}) et
 * l'analyse inter-procédurale ({@link InterproceduralAnalyzer}).
 */
export class TaintRuleSet {
    private readonly sources: string[];
    private readonly sinkTypes: Map<string, string>;
    private readonly sanitizers: string[];

    constructor(rules: Rules) {
        this.sources = rules.sources;
        this.sinkTypes = new Map((rules.sinks ?? DEFAULT_SINKS).map(sink => [sink.name, sink.type]));
        this.sanitizers = rules.sanitizers ?? DEFAULT_SANITIZERS;
    }

    /** Vrai si le texte est un accès à une superglobale source, direct ou indexé. */
    isSource(text: string): boolean {
        return this.sources.some(source => text === source || text.startsWith(`${source}[`));
    }

    /** Catégorie de vulnérabilité si `name` est un sink, sinon `null`. */
    sinkType(name: string): string | null {
        return this.sinkTypes.get(name) ?? null;
    }

    /** Vrai si l'expression applique un désinfectant (appel `sanitizer(...)` ou cast `(int)`, …). */
    isSanitizedExpression(text: string): boolean {
        return this.sanitizers.some(sanitizer => {
            if (sanitizer.startsWith('(')) {
                return text.includes(sanitizer); // cast, ex. (int)
            }
            return new RegExp(`(^|[^A-Za-z0-9_$])${escapeRegExp(sanitizer)}\\s*\\(`).test(text);
        });
    }

    /** Variables neutralisées par un désinfectant à l'intérieur de leur propre argument. */
    sanitizedVariables(argumentExpressions?: CallArgument[]): Set<string> {
        const sanitized = new Set<string>();
        for (const arg of argumentExpressions ?? []) {
            if (this.isSanitizedExpression(arg.text)) {
                for (const variable of arg.variables) {
                    sanitized.add(variable);
                }
            }
        }
        return sanitized;
    }

    /** Sous-ensemble de `tainted` dont le nom apparaît comme jeton entier dans `text`. */
    taintedVarsIn(text: string, tainted: Iterable<string>): string[] {
        const found: string[] = [];
        for (const variable of tainted) {
            if (new RegExp(`${escapeRegExp(variable)}(?![A-Za-z0-9_])`).test(text)) {
                found.push(variable);
            }
        }
        return found;
    }

    /** Vrai si `text` référence au moins une variable teintée. */
    containsTaintedVar(text: string, tainted: Iterable<string>): boolean {
        return this.taintedVarsIn(text, tainted).length > 0;
    }
}

export function escapeRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
