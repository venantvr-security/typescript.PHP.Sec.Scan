import {expect} from 'chai';

import treeSitterPhp from 'tree-sitter-php';
import Parser = require('tree-sitter');

import {SyntaxTreeParser} from '../src/syntaxTreeParser';
import {TaintAnalyzer} from '../src/taintTracker';
import {exportTaintGraph} from '../src/taintGraph';
import {HolonGraph, Rules} from '../src/types';

const rules: Rules = {sources: ['$_GET', '$_POST']};
const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

function taintGraph(code: string): HolonGraph {
    const source = Buffer.from(code, 'utf-8');
    const events = new SyntaxTreeParser(source, parser.parse(code) as any, 't.php').parse();
    const analyzer = new TaintAnalyzer(rules, 't.php');
    analyzer.analyze(events);
    return exportTaintGraph(analyzer.getTaintFlow(), '2026-07-14T10:30:00.000Z');
}

function node(graph: HolonGraph, name: string) {
    return graph.nodes.find(n => n.data.name === name);
}

function edgeBetween(graph: HolonGraph, fromName: string, toName: string) {
    const from = node(graph, fromName);
    const to = node(graph, toName);
    return graph.edges.find(e => e.sourceId === from?.id && e.targetId === to?.id);
}

describe('exportTaintGraph', () => {
    it('relie source → variable → sink pour une injection SQL', () => {
        const graph = taintGraph(`<?php $id = $_GET['id']; mysqli_query($id);`);

        expect(node(graph, "$_GET['id']")!.data.archimateType).to.equal('Source');
        expect(node(graph, '$id')!.data.archimateType).to.equal('Variable teintée');
        expect(node(graph, 'mysqli_query')!.data.archimateType).to.equal('Sink (vulnérabilité)');

        expect(edgeBetween(graph, "$_GET['id']", '$id')!.data.relationType).to.equal('Flux');
        const vuln = edgeBetween(graph, '$id', 'mysqli_query')!;
        expect(vuln.data.relationType).to.equal('Vulnérabilité');
        expect(vuln.data.name).to.equal('sql_injection');
    });

    it('représente la propagation entre variables', () => {
        const graph = taintGraph(`<?php $id = $_GET['id']; $tmp = $id; echo $tmp;`);
        expect(edgeBetween(graph, '$id', '$tmp')!.data.relationType).to.equal('Flux');
        expect(edgeBetween(graph, '$tmp', 'echo')!.data.relationType).to.equal('Vulnérabilité');
    });

    it('marque une désinfection en vert et n\'émet pas de vulnérabilité', () => {
        const graph = taintGraph(`<?php $x = $_GET['x']; $safe = htmlspecialchars($x); echo $safe;`);
        expect(node(graph, '$safe')!.data.archimateType).to.equal('Désinfectée');
        expect(edgeBetween(graph, '$x', '$safe')!.data.relationType).to.equal('Désinfection');
        expect(graph.edges.some(e => e.data.relationType === 'Vulnérabilité')).to.be.false;
    });

    it('classe la géométrie en couches (source à gauche du sink)', () => {
        const graph = taintGraph(`<?php $id = $_GET['id']; mysqli_query($id);`);
        const src = node(graph, "$_GET['id']")!.geometry.x;
        const variable = node(graph, '$id')!.geometry.x;
        const sink = node(graph, 'mysqli_query')!.geometry.x;
        expect(src).to.be.lessThan(variable);
        expect(variable).to.be.lessThan(sink);
    });
});
