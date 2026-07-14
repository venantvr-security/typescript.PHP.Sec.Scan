import {expect} from 'chai';

import treeSitterPhp from 'tree-sitter-php';
import Parser = require('tree-sitter');

import {DependencyGraphBuilder} from '../src/dependencyGraph';
import {exportDependencyGraph} from '../src/holonExporter';
import {renderHolonGraphToHtml} from '../src/renderHtml';

const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

function html(code: string): string {
    const builder = new DependencyGraphBuilder();
    builder.addFile('a.php', parser.parse(code) as any, Buffer.from(code, 'utf-8'));
    return renderHolonGraphToHtml(exportDependencyGraph(builder.build(), '2026-07-14T10:30:00.000Z'));
}

describe('renderHolonGraphToHtml', () => {
    const doc = html(`<?php class C { function m() { helper(); new C(); } } function helper() {}`);

    it('produit un document HTML autonome, sans ressource externe', () => {
        expect(doc.startsWith('<!doctype html>')).to.be.true;
        expect(doc).to.contain('<svg');
        // Aucune requête réseau : seule l'URL de namespace SVG du W3C est autorisée.
        const externalUrls = doc.match(/https?:\/\/[^"'\s]+/g) ?? [];
        expect(externalUrls.every(u => u.startsWith('http://www.w3.org/'))).to.be.true;
    });

    it('dessine un rectangle par nœud et une ligne par arête', () => {
        const builder = new DependencyGraphBuilder();
        const code = `<?php class C { function m() { helper(); new C(); } } function helper() {}`;
        builder.addFile('a.php', parser.parse(code) as any, Buffer.from(code, 'utf-8'));
        const graph = exportDependencyGraph(builder.build(), '2026-07-14T10:30:00.000Z');
        const rendered = renderHolonGraphToHtml(graph);

        expect((rendered.match(/<rect /g) ?? []).length).to.equal(graph.metadata.nodeCount);
        expect((rendered.match(/<line /g) ?? []).length).to.equal(graph.metadata.edgeCount);
    });

    it('échappe le contenu textuel injecté dans le SVG', () => {
        const evil = html(`<?php function foo() { bar(); }`).includes('<script>');
        expect(evil).to.be.false;
    });
});
