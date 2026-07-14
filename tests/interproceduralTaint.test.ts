import {expect} from 'chai';

import treeSitterPhp from 'tree-sitter-php';
import Parser = require('tree-sitter');

import {SyntaxTreeParser} from '../src/syntaxTreeParser';
import {InterproceduralAnalyzer} from '../src/interproceduralTaint';
import {Rules, Vulnerability} from '../src/types';

const rules: Rules = {sources: ['$_GET', '$_POST']};
const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

function analyze(code: string): Vulnerability[] {
    const source = Buffer.from(code, 'utf-8');
    const module = new SyntaxTreeParser(source, parser.parse(code) as any, 'a.php').parseModule();
    return new InterproceduralAnalyzer(rules).analyze([module]).vulnerabilities;
}

function errors(code: string): Vulnerability[] {
    return analyze(code).filter(v => v.severity === 'error');
}

describe('InterproceduralAnalyzer', () => {
    it('détecte un sink atteint via une fonction wrapper appelée', () => {
        const errs = errors(`<?php function wrap($sql) { mysqli_query($sql); } $id = $_GET['id']; wrap($id);`);
        expect(errs).to.have.lengthOf(1);
        expect(errs[0].type).to.equal('sql_injection');
        expect(errs[0].trace).to.contain('wrap');
    });

    it('propage la teinte à travers deux niveaux d\'appel', () => {
        const errs = errors(`<?php function a($x){ b($x); } function b($y){ system($y); } $c = $_GET['c']; a($c);`);
        expect(errs).to.have.lengthOf(1);
        expect(errs[0].type).to.equal('rce');
        expect(errs[0].trace).to.contain('a → b');
    });

    it('propage la teinte du retour d\'une fonction vers l\'appelant', () => {
        const errs = errors(`<?php function identity($v){ return $v; } $id = $_GET['id']; $out = identity($id); echo $out;`);
        expect(errs.some(v => v.type === 'xss')).to.be.true;
    });

    it('ne signale rien si la fonction appelée désinfecte son retour', () => {
        const errs = errors(`<?php function clean($v){ return htmlspecialchars($v); } $id = $_GET['id']; $out = clean($id); echo $out;`);
        expect(errs).to.be.empty;
    });

    it('ne signale rien si l\'argument est désinfecté avant l\'appel', () => {
        const errs = errors(`<?php function wrap($sql){ mysqli_query($sql); } $id = $_GET['id']; wrap(intval($id));`);
        expect(errs).to.be.empty;
    });

    it('ne signale rien si la fonction appelée reçoit une donnée saine', () => {
        const errs = errors(`<?php function wrap($sql){ mysqli_query($sql); } $id = "42"; wrap($id);`);
        expect(errs).to.be.empty;
    });

    it('termine sur une fonction récursive et détecte quand même le sink', () => {
        const errs = errors(`<?php function rec($x){ rec($x); system($x); } $id = $_GET['id']; rec($id);`);
        expect(errs.some(v => v.type === 'rce')).to.be.true;
    });

    it('suit la teinte à travers un appel de méthode ($this->)', () => {
        const errs = errors(`<?php class Repo { function run($sql){ mysqli_query($sql); } function find($id){ return $this->run($id); } } $x = $_GET['x']; (new Repo())->find($x);`);
        expect(errs.some(v => v.type === 'sql_injection')).to.be.true;
    });
});
