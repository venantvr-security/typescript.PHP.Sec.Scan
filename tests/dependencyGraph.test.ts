import {expect} from 'chai';

import treeSitterPhp from 'tree-sitter-php';
import Parser = require('tree-sitter');

import {DependencyGraphBuilder} from '../src/dependencyGraph';
import {exportDependencyGraph} from '../src/holonExporter';
import {HolonGraph} from '../src/types';

const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

function graphFrom(files: Record<string, string>): HolonGraph {
    const builder = new DependencyGraphBuilder();
    for (const [name, code] of Object.entries(files)) {
        const source = Buffer.from(code, 'utf-8');
        builder.addFile(name, parser.parse(code) as any, source);
    }
    return exportDependencyGraph(builder.build(), '2026-07-14T10:30:00.000Z');
}

function node(graph: HolonGraph, name: string) {
    return graph.nodes.find(n => n.data.name === name);
}

describe('DependencyGraph / HolonExporter', () => {
    it('produit un document Holon conforme au schéma', () => {
        const graph = graphFrom({'a.php': `<?php function foo() { bar(); } function bar() {}`});

        expect(graph.version).to.equal('1.0');
        expect(graph.exportedAt).to.equal('2026-07-14T10:30:00.000Z');
        expect(graph.metadata.nodeCount).to.equal(graph.nodes.length);
        expect(graph.metadata.edgeCount).to.equal(graph.edges.length);
        expect(graph.metadata.exportTool).to.be.a('string').and.not.empty;

        for (const n of graph.nodes) {
            expect(n).to.have.all.keys('id', 'parentId', 'type', 'geometry', 'styling', 'data');
            expect(n.geometry).to.have.all.keys('x', 'y', 'w', 'h');
            expect(n.styling).to.have.all.keys('fill', 'stroke', 'strokeWidth', 'opacity');
            expect(n.data).to.have.all.keys('name', 'archimateType', 'documentation');
        }
        for (const e of graph.edges) {
            expect(e).to.have.all.keys('id', 'sourceId', 'targetId', 'routing', 'data');
            expect(e.data).to.have.all.keys('relationType', 'name');
        }
    });

    it('crée un nœud par fonction et une arête par appel résolu', () => {
        const graph = graphFrom({'a.php': `<?php function foo() { bar(); } function bar() {}`});

        const foo = node(graph, 'foo');
        const bar = node(graph, 'bar');
        expect(foo, 'foo node').to.exist;
        expect(bar, 'bar node').to.exist;
        expect(graph.edges.some(e => e.sourceId === foo!.id && e.targetId === bar!.id)).to.be.true;
    });

    it('résout les dépendances entre fichiers', () => {
        const graph = graphFrom({
            'app.php': `<?php function main() { helper(); }`,
            'lib.php': `<?php function helper() {}`
        });

        const main = node(graph, 'main');
        const helper = node(graph, 'helper');
        expect(helper!.data.documentation).to.contain('lib.php');
        const edge = graph.edges.find(e => e.sourceId === main!.id && e.targetId === helper!.id);
        expect(edge, 'cross-file edge').to.exist;
        expect(edge!.data.relationType).to.equal('Triggering');
    });

    it('résout les appels de méthode via $this et imbrique les méthodes dans la classe', () => {
        const graph = graphFrom({
            'r.php': `<?php class Repo { function a() { return $this->b(); } function b() {} }`
        });

        const repo = node(graph, 'Repo')!;
        const a = node(graph, 'a')!;
        const b = node(graph, 'b')!;
        expect(a.parentId).to.equal(repo.id);
        expect(b.parentId).to.equal(repo.id);
        expect(repo.type).to.equal('container');
        expect(graph.edges.some(e => e.sourceId === a.id && e.targetId === b.id && e.data.relationType === 'Triggering')).to.be.true;
    });

    it('modélise l\'instanciation comme une relation Association', () => {
        const graph = graphFrom({
            'm.php': `<?php class Widget {} function build() { return new Widget(); }`
        });

        const build = node(graph, 'build')!;
        const widget = node(graph, 'Widget')!;
        const edge = graph.edges.find(e => e.sourceId === build.id && e.targetId === widget.id);
        expect(edge, 'instantiation edge').to.exist;
        expect(edge!.data.relationType).to.equal('Association');
    });

    it('représente les symboles non définis comme des nœuds externes (aucune arête pendante)', () => {
        const graph = graphFrom({'a.php': `<?php function foo() { trim($x); }`});

        const trim = node(graph, 'trim')!;
        expect(trim.data.documentation.toLowerCase()).to.contain('external');
        const ids = new Set(graph.nodes.map(n => n.id));
        for (const e of graph.edges) {
            expect(ids.has(e.sourceId), `source ${e.sourceId}`).to.be.true;
            expect(ids.has(e.targetId), `target ${e.targetId}`).to.be.true;
        }
    });

    it('garantit l\'intégrité référentielle des parents et des arêtes', () => {
        const graph = graphFrom({
            'app.php': `<?php class C { function m() { free(); new C(); } }`
        });

        const ids = new Set(graph.nodes.map(n => n.id));
        for (const n of graph.nodes) {
            if (n.parentId !== null) {
                expect(ids.has(n.parentId), `parent of ${n.id}`).to.be.true;
            }
        }
        for (const e of graph.edges) {
            expect(ids.has(e.sourceId)).to.be.true;
            expect(ids.has(e.targetId)).to.be.true;
        }
    });
});
