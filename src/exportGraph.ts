import * as fs from 'fs';
import * as path from 'path';

import Parser = require('tree-sitter');
import treeSitterPhp = require('tree-sitter-php');

import {DependencyGraphBuilder} from './dependencyGraph';
import {exportDependencyGraph} from './holonExporter';
import {renderHolonGraphToHtml} from './renderHtml';

interface CliOptions {
    inputs: string[];
    out: string | null;
    html: string | null;
}

function parseArgs(argv: string[]): CliOptions {
    const inputs: string[] = [];
    let out: string | null = null;
    let html: string | null = null;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--out' || arg === '-o') {
            out = argv[++i] ?? null;
        } else if (arg === '--html') {
            html = argv[++i] ?? null;
        } else if (arg === '--help' || arg === '-h') {
            printUsage();
            process.exit(0);
        } else {
            inputs.push(arg);
        }
    }
    return {inputs, out, html};
}

function printUsage(): void {
    console.error(`Usage: export-graph <file-or-dir> [more paths...] [--out graph.json] [--html preview.html]

Statically analyses PHP sources and exports an AST dependency graph in the
Holon Architecture Modeler format. Without --out, the JSON is written to stdout.
Use --html to also write a self-contained SVG preview of the graph.`);
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

    const builder = new DependencyGraphBuilder();
    for (const file of files) {
        const source = fs.readFileSync(file);
        const tree = parser.parse(source.toString('utf-8'));
        builder.addFile(file, tree, source);
    }

    const model = builder.build();
    const graph = exportDependencyGraph(model, new Date().toISOString());
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
