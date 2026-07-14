import {expect} from 'chai';

import treeSitterPhp from 'tree-sitter-php';
import Parser = require('tree-sitter');

import {DependencyGraphBuilder} from '../src/dependencyGraph';
import {exportDependencyGraph} from '../src/holonExporter';
import {SyntaxTreeParser} from '../src/syntaxTreeParser';
import {InterproceduralAnalyzer} from '../src/interproceduralTaint';
import {exportUnifiedGraph} from '../src/unifiedGraph';
import {HolonGraph, Rules} from '../src/types';

const rules: Rules = {sources: ['$_GET', '$_POST']};
const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

function unified(code: string): HolonGraph {
    const source = Buffer.from(code, 'utf-8');
    const tree = parser.parse(code) as any;
    const builder = new DependencyGraphBuilder();
    builder.addFile('a.php', tree, source);
    const dependencyGraph = exportDependencyGraph(builder.build(), '2026-07-14T10:30:00.000Z');
    const module = new SyntaxTreeParser(source, tree, 'a.php').parseModule();
    const {vulnerabilities, flow} = new InterproceduralAnalyzer(rules).analyze([module]);
    return exportUnifiedGraph(dependencyGraph, vulnerabilities, flow);
}

function node(graph: HolonGraph, name: string) {
    return graph.nodes.find(n => n.data.name === name);
}

describe('exportUnifiedGraph', () => {
    const graph = unified(`<?php
        function wrap($sql) { mysqli_query($sql); }
        function handle() { $id = $_GET['id']; wrap($id); }
    `);

    it('colore en rouge la fonction où le sink est atteint', () => {
        const wrap = node(graph, 'wrap')!;
        expect(wrap.styling.stroke).to.equal('#c62828');
        expect(wrap.data.documentation).to.contain('Vulnérable');
        expect(wrap.data.documentation).to.contain('sql_injection');
    });

    it('ne colore pas en rouge une fonction non concernée', () => {
        const handle = node(graph, 'handle')!;
        expect(handle.styling.stroke).to.not.equal('#c62828');
    });

    it('met en évidence l\'arête d\'appel qui transporte la teinte', () => {
        const handle = node(graph, 'handle')!;
        const wrap = node(graph, 'wrap')!;
        const edge = graph.edges.find(e => e.sourceId === handle.id && e.targetId === wrap.id);
        expect(edge, 'arête handle → wrap').to.exist;
        expect(edge!.data.relationType).to.equal('Flux');
    });

    it('conserve l\'intégrité référentielle après la surcouche', () => {
        const ids = new Set(graph.nodes.map(n => n.id));
        for (const e of graph.edges) {
            expect(ids.has(e.sourceId), `source ${e.sourceId}`).to.be.true;
            expect(ids.has(e.targetId), `target ${e.targetId}`).to.be.true;
        }
        expect(graph.metadata.exportTool).to.contain('unified');
    });
});
