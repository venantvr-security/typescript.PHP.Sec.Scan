import {expect} from 'chai';
import {Rules} from '../src/types';

import treeSitterPhp from 'tree-sitter-php';
import {TaintAnalyzer} from "../src/taintTracker";
import {SyntaxTreeParser} from "../src/syntaxTreeParser";
import Parser = require("tree-sitter");

// Configuration des règles pour les tests
const rules: Rules = {
    sources: ['$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES']
};

// Initialisation du parseur
const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

describe('TaintAnalyzer', () => {
    it('devrait détecter une source non désinfectée', () => {
        const code = `
            <?php
            $id = $_GET['id'];
            $name = $id;
            ?>
        `;
        const tree = parser.parse(code);
        const parserInstance = new SyntaxTreeParser(Buffer.from(code, 'utf-8'), tree, 'test.php');
        const events = parserInstance.parse();
        const analyzer = new TaintAnalyzer(rules, 'test.php');
        const vulnerabilities = analyzer.analyze(events);
        expect(vulnerabilities).to.have.lengthOf(2); // 2 avertissements (source + propagation)
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$name' && v.severity === 'warning')).to.be.true;

        const taintFlow = analyzer.printTaintFlow();
        expect(taintFlow).to.include("Variable '$id' assigned from source '$_GET['id']'");
        expect(taintFlow).to.include("Variable '$name' assigned from source '$id'");
    });

    it('devrait détecter une variable tainted passée à une fonction', () => {
        const code = `
            <?php
            $id = $_GET['id'];
            some_function($id);
            ?>
        `;
        const tree = parser.parse(code);
        const parserInstance = new SyntaxTreeParser(Buffer.from(code, 'utf-8'), tree, 'test.php');
        const events = parserInstance.parse();
        const analyzer = new TaintAnalyzer(rules, 'test.php');
        const vulnerabilities = analyzer.analyze(events);
        expect(vulnerabilities).to.have.lengthOf(1); // 1 avertissement pour source
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;

        const taintFlow = analyzer.printTaintFlow();
        expect(taintFlow).to.include("Variable '$id' assigned from source '$_GET['id']'");
        expect(taintFlow).to.include("Variable '$id' passed as parameter to function 'some_function'");
    });

    it('devrait détecter une variable tainted passée à une fonction après 2 affectations', () => {
        const code = `
            <?php
            $tmp = $_GET['id'];
            $id = $tmp;
            some_function($id);
            ?>
        `;
        const tree = parser.parse(code);
        const parserInstance = new SyntaxTreeParser(Buffer.from(code, 'utf-8'), tree, 'test.php');
        const events = parserInstance.parse();
        const analyzer = new TaintAnalyzer(rules, 'test.php');
        const vulnerabilities = analyzer.analyze(events);
        expect(vulnerabilities).to.have.lengthOf(2); // 1 avertissement pour source
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;

        const taintFlow = analyzer.printTaintFlow();
        expect(taintFlow).to.include("Variable '$tmp' assigned from source '$_GET['id']'");
        expect(taintFlow).to.include("Variable '$id' assigned from source '$tmp'")
        expect(taintFlow).to.include("Variable '$id' passed as parameter to function 'some_function'");
    });

    it('devrait détecter une variable tainted passée à une fonction après 2 affectations et un appel de méthode', () => {
        const code = `
            <?php
            function some_function($param) {
                return $param;
            }
            $tmp = $_GET['id'];
            $id = $tmp;
            some_function($id);
            ?>
        `;
        const tree = parser.parse(code);
        const parserInstance = new SyntaxTreeParser(Buffer.from(code, 'utf-8'), tree, 'test.php');
        const events = parserInstance.parse();
        const analyzer = new TaintAnalyzer(rules, 'test.php');
        const vulnerabilities = analyzer.analyze(events);
        expect(vulnerabilities).to.have.lengthOf(2); // 2 avertissement pour source
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;

        const taintFlow = analyzer.printTaintFlow();
        // console.log(taintFlow);
        expect(taintFlow).to.include("Variable '$tmp' assigned from source '$_GET['id']'");
        expect(taintFlow).to.include("Variable '$id' assigned from source '$tmp'")
        expect(taintFlow).to.include("Variable '$id' passed as parameter to function 'some_function'");
    });

    function analyze(code: string) {
        const tree = parser.parse(code);
        const events = new SyntaxTreeParser(Buffer.from(code, 'utf-8'), tree, 'test.php').parse();
        return new TaintAnalyzer(rules, 'test.php').analyze(events);
    }

    it('signale une injection SQL quand une donnée teintée atteint un sink SQL', () => {
        const vulns = analyze(`<?php $id = $_GET['id']; mysqli_query($id);`);
        const sqli = vulns.find(v => v.type === 'sql_injection');
        expect(sqli, 'vulnérabilité SQL').to.exist;
        expect(sqli!.severity).to.equal('error');
        expect(sqli!.sink).to.equal('mysqli_query');
    });

    it('signale un XSS quand une donnée teintée atteint un echo', () => {
        const vulns = analyze(`<?php $name = $_GET['name']; echo $name;`);
        const xss = vulns.find(v => v.type === 'xss');
        expect(xss, 'vulnérabilité XSS').to.exist;
        expect(xss!.severity).to.equal('error');
        expect(xss!.sink).to.equal('echo');
    });

    it('signale une RCE quand une donnée teintée atteint eval', () => {
        const vulns = analyze(`<?php $c = $_GET['c']; eval($c);`);
        expect(vulns.some(v => v.type === 'rce' && v.severity === 'error' && v.sink === 'eval')).to.be.true;
    });

    it('ne signale aucune vulnérabilité de sink après désinfection', () => {
        const vulns = analyze(`<?php $id = $_GET['id']; $safe = htmlspecialchars($id); echo $safe;`);
        expect(vulns.some(v => v.severity === 'error')).to.be.false;
        // Seul l'avertissement de source subsiste.
        expect(vulns).to.have.lengthOf(1);
        expect(vulns[0].type).to.equal('unsanitized_source');
    });

    it('ne considère pas un appel de fonction anodin comme un sink', () => {
        const vulns = analyze(`<?php $id = $_GET['id']; some_function($id);`);
        expect(vulns.some(v => v.severity === 'error')).to.be.false;
    });

    it('ne signale pas de vulnérabilité si la donnée est désinfectée dans l\'argument du sink', () => {
        const escaped = analyze(`<?php $id = $_GET['id']; mysqli_query(mysqli_real_escape_string($id));`);
        expect(escaped.some(v => v.severity === 'error'), 'escape intra-argument').to.be.false;

        const cast = analyze(`<?php $id = $_GET['id']; system(intval($id));`);
        expect(cast.some(v => v.severity === 'error'), 'intval intra-argument').to.be.false;
    });

    it('signale toujours la vulnérabilité si l\'argument du sink n\'est pas désinfecté', () => {
        const vulns = analyze(`<?php $id = $_GET['id']; mysqli_query($id);`);
        expect(vulns.some(v => v.type === 'sql_injection' && v.severity === 'error')).to.be.true;
    });
});