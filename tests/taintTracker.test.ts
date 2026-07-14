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
});