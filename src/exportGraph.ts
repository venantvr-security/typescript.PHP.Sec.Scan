import * as fs from 'fs';
import * as path from 'path';

import Parser = require('tree-sitter');
import treeSitterPhp = require('tree-sitter-php');

import {DependencyGraphBuilder} from './dependencyGraph';
import {exportDependencyGraph} from './holonExporter';
import {SyntaxTreeParser} from './syntaxTreeParser';
import {InterproceduralAnalyzer} from './interproceduralTaint';
import {exportTaintGraph} from './taintGraph';
import {exportUnifiedGraph} from './unifiedGraph';
import {renderHolonGraphToHtml} from './renderHtml';
import {HolonGraph, ModuleModel, Rules} from './types';

const DEFAULT_SOURCES = ['$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES'];

type GraphKind = 'dependency' | 'taint' | 'unified';

interface CliOptions {
    inputs: string[];
    out: string | null;
    html: string | null;
    kind: GraphKind;
}

function parseArgs(argv: string[]): CliOptions {
    const inputs: string[] = [];
    let out: string | null = null;
    let html: string | null = null;
    let kind: GraphKind = 'dependency';
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--out' || arg === '-o') {
            out = argv[++i] ?? null;
        } else if (arg === '--html') {
            html = argv[++i] ?? null;
        } else if (arg === '--taint') {
            kind = 'taint';
        } else if (arg === '--unified') {
            kind = 'unified';
        } else if (arg === '--help' || arg === '-h') {
            printUsage();
            process.exit(0);
        } else {
            inputs.push(arg);
        }
    }
    return {inputs, out, html, kind};
}

function printUsage(): void {
    console.error(`Usage: export-graph <file-or-dir> [more paths...] [options]

Options:
  --taint          Export the taint graph (source -> sink) instead of the
                   dependency graph.
  --unified        Export the dependency graph with an inter-procedural taint
                   overlay (vulnerable nodes in red, tainted calls in orange).
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

function parseModules(parser: Parser, files: string[]): ModuleModel[] {
    return files.map(file => {
        const source = fs.readFileSync(file);
        return new SyntaxTreeParser(source, parser.parse(source.toString('utf-8')), file).parseModule();
    });
}

function buildTaintGraph(parser: Parser, files: string[]): HolonGraph {
    const {flow} = new InterproceduralAnalyzer({sources: DEFAULT_SOURCES}).analyze(parseModules(parser, files));
    return exportTaintGraph(flow, new Date().toISOString());
}

function buildUnifiedGraph(parser: Parser, files: string[]): HolonGraph {
    const dependencyGraph = buildDependencyGraph(parser, files);
    const {vulnerabilities, flow} = new InterproceduralAnalyzer({sources: DEFAULT_SOURCES}).analyze(parseModules(parser, files));
    return exportUnifiedGraph(dependencyGraph, vulnerabilities, flow);
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

    const graph = options.kind === 'taint'
        ? buildTaintGraph(parser, files)
        : options.kind === 'unified'
            ? buildUnifiedGraph(parser, files)
            : buildDependencyGraph(parser, files);
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
