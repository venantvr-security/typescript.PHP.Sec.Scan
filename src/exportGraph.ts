import * as fs from 'fs';
import * as path from 'path';

import Parser = require('tree-sitter');
import treeSitterPhp = require('tree-sitter-php');

import {DependencyGraphBuilder} from './dependencyGraph';
import {exportDependencyGraph} from './holonExporter';
import {SyntaxTreeParser} from './syntaxTreeParser';
import {TaintAnalyzer} from './taintTracker';
import {exportTaintGraph} from './taintGraph';
import {renderHolonGraphToHtml} from './renderHtml';
import {HolonGraph, Rules, TaintFlowEntry} from './types';

const DEFAULT_SOURCES = ['$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES'];

interface CliOptions {
    inputs: string[];
    out: string | null;
    html: string | null;
    taint: boolean;
}

function parseArgs(argv: string[]): CliOptions {
    const inputs: string[] = [];
    let out: string | null = null;
    let html: string | null = null;
    let taint = false;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--out' || arg === '-o') {
            out = argv[++i] ?? null;
        } else if (arg === '--html') {
            html = argv[++i] ?? null;
        } else if (arg === '--taint') {
            taint = true;
        } else if (arg === '--help' || arg === '-h') {
            printUsage();
            process.exit(0);
        } else {
            inputs.push(arg);
        }
    }
    return {inputs, out, html, taint};
}

function printUsage(): void {
    console.error(`Usage: export-graph <file-or-dir> [more paths...] [options]

Options:
  --taint          Export the taint graph (source -> sink) instead of the
                   dependency graph.
  --out <file>     Write the Holon JSON document (default: stdout).
  --html <file>    Also write a self-contained SVG preview of the graph.

Statically analyses PHP sources and exports an AST-based graph in the Holon
Architecture Modeler format.`);
}

function collectPhpFiles(target: string, acc: string[]): void {
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
        for (const entry of fs.readdirSync(target)) {
            if (entry === 'node_modules' || entry === 'vendor' || entry.startsWith('.')) {
                continue;
            }
            collectPhpFiles(path.join(target, entry), acc);
        }
    } else if (stat.isFile() && target.endsWith('.php')) {
        acc.push(target);
    }
}

function buildDependencyGraph(parser: Parser, files: string[]): HolonGraph {
    const builder = new DependencyGraphBuilder();
    for (const file of files) {
        const source = fs.readFileSync(file);
        builder.addFile(file, parser.parse(source.toString('utf-8')), source);
    }
    return exportDependencyGraph(builder.build(), new Date().toISOString());
}

function buildTaintGraph(parser: Parser, files: string[]): HolonGraph {
    const rules: Rules = {sources: DEFAULT_SOURCES};
    const flow: TaintFlowEntry[] = [];
    for (const file of files) {
        const source = fs.readFileSync(file);
        const tree = parser.parse(source.toString('utf-8'));
        const events = new SyntaxTreeParser(source, tree, file).parse();
        const analyzer = new TaintAnalyzer(rules, file);
        analyzer.analyze(events);
        flow.push(...analyzer.getTaintFlow());
    }
    return exportTaintGraph(flow, new Date().toISOString());
}

function main(): void {
    const options = parseArgs(process.argv.slice(2));
    if (options.inputs.length === 0) {
        printUsage();
        process.exit(1);
    }

    const files: string[] = [];
    for (const input of options.inputs) {
        if (!fs.existsSync(input)) {
            console.error(`Path not found: ${input}`);
            process.exit(1);
        }
        collectPhpFiles(input, files);
    }

    if (files.length === 0) {
        console.error('No .php files found in the given paths.');
        process.exit(1);
    }

    const parser = new Parser();
    parser.setLanguage(treeSitterPhp.php);

    const graph = options.taint ? buildTaintGraph(parser, files) : buildDependencyGraph(parser, files);
    const json = JSON.stringify(graph, null, 2);

    if (options.html) {
        fs.writeFileSync(options.html, renderHolonGraphToHtml(graph), 'utf-8');
        console.error(`Wrote SVG preview to ${options.html}`);
    }

    if (options.out) {
        fs.writeFileSync(options.out, json, 'utf-8');
        console.error(`Wrote ${graph.metadata.nodeCount} nodes and ${graph.metadata.edgeCount} edges to ${options.out}`);
    } else if (!options.html) {
        process.stdout.write(json + '\n');
    }
}

main();
