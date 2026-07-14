# PHP Security Scanner

Une extension Visual Studio Code pour détecter les vulnérabilités de sécurité dans le code PHP en utilisant le suivi des taints (*taint tracking*).

## Description

PHP Security Scanner analyse le code PHP pour identifier des vulnérabilités courantes telles que :

- Injections SQL
- Cross-Site Scripting (XSS)
- Exécution de code à distance (RCE)
- Inclusion de fichiers
- Contournement d'authentification
- Fixation de session
- Téléchargements de fichiers non sécurisés

L'extension utilise `tree-sitter` et `tree-sitter-php` pour parser le code PHP et effectue un suivi des données non sécurisées (taint tracking) basé sur un ensemble de règles définies dans `rules.yaml`. Elle fournit des diagnostics dans le panneau des problèmes de VS Code et propose des actions de code (*quick fixes*) pour corriger automatiquement certaines vulnérabilités, comme remplacer `==` par `===` ou ajouter `htmlspecialchars`.

## Fonctionnalités

- Analyse statique du code PHP pour détecter les vulnérabilités.
- Diagnostics avec messages d'erreur et d'avertissement.
- Actions de code pour des corrections automatiques (ex. désinfection XSS, comparaisons strictes).
- Configuration personnalisable via `settings.json` et `rules.yaml`.
- Support pour l'analyse automatique à la sauvegarde des fichiers PHP.
- **Export d'un graphe de dépendances** (basé sur l'AST) au format Holon Architecture Modeler.

## Graphe de dépendances (export Holon)

À partir de l'AST `tree-sitter`, le scanner construit un graphe de dépendances
à l'échelle du projet et l'exporte au format JSON de **Holon Architecture Modeler**.

- **Nœuds** : fichiers (conteneurs), classes/interfaces/traits (conteneurs),
  fonctions et méthodes. Les méthodes sont imbriquées dans leur classe, et les
  classes/fonctions dans leur fichier.
- **Arêtes** : appels de fonction, appels de méthode (`$this->m()`), appels
  statiques (`Foo::bar()`) → `Triggering` ; instanciations (`new Foo()`) →
  `Association`. La résolution des symboles est effectuée **entre fichiers**.
- **Symboles externes** : toute référence non définie dans les sources
  analysées (fonctions natives PHP, code tiers) devient un nœud `external`,
  de sorte qu'aucune arête ne pointe dans le vide.
- **Géométrie** : une mise en page hiérarchique déterministe assigne
  `x/y/w/h` à chaque nœud pour un rendu immédiat dans Holon.

Chaque nœud reçoit un type ArchiMate (`ApplicationComponent`,
`ApplicationFunction`, `ApplicationService`) et un style, conformément au
schéma attendu par Holon (`version`, `nodes`, `edges`, `metadata`).

### Utilisation en ligne de commande

```bash
# Analyser un dossier (récursif, ignore vendor/node_modules) et écrire le JSON
npm run export-graph -- ./chemin/vers/projet-php --out graphe.json

# Générer aussi un aperçu HTML/SVG autonome (ouvrable dans un navigateur)
npm run export-graph -- ./chemin/vers/projet-php --out graphe.json --html apercu.html

# Exporter le graphe de TEINTE (source → sink) au lieu des dépendances
npm run export-graph -- ./chemin/vers/projet-php --taint --html teinte.html

# Exporter la vue UNIFIÉE (dépendances + surcouche de teinte)
npm run export-graph -- ./chemin/vers/projet-php --unified --html unifie.html

# Ou écrire sur stdout (JSON pur, pipeable)
node out/src/exportGraph.js ./src/fichier.php
```

Trois graphes sont disponibles, tous au format Holon et affichables via
`--html` :

- **Dépendances** (par défaut) : fichiers, classes, fonctions et méthodes,
  reliés par les appels et instanciations.
- **Teinte** (`--taint`) : le trajet des données depuis les **sources** vers
  les **sinks**, avec code couleur — flux (orange), désinfection (vert),
  vulnérabilité (rouge), usage anodin (gris). Le suivi est **inter-procédural**
  (voir ci-dessous) : les arêtes traversent les appels de fonctions/méthodes.
- **Unifié** (`--unified`) : la structure du graphe de dépendances enrichie
  d'une surcouche de teinte — les fonctions où un sink est atteint sont en
  **rouge**, les appels qui transportent une donnée teintée en **orange**.

L'aperçu HTML (`--html`) est un fichier **autonome** (SVG inline, aucune
ressource externe) : conteneurs imbriqués, couleurs par type ArchiMate,
arêtes fléchées et étiquetées, légende. Le survol d'un nœud affiche sa
documentation.

## Analyse de teinte : sources, sinks et désinfectants

La détection de vulnérabilités suit le trajet d'une donnée depuis une **source**
jusqu'à un **sink** :

- **Source** → **sink** sans désinfection ⇒ vulnérabilité (`severity: error`),
  typée selon le sink : `sql_injection`, `xss`, `rce`, `file_inclusion`.
- Une donnée qui passe par un **désinfectant** (`htmlspecialchars`, `intval`,
  `mysqli_real_escape_string`, cast `(int)`, …) redevient sûre. La désinfection
  est détectée aussi bien lors d'une affectation (`$s = htmlspecialchars($x)`)
  que **directement dans l'argument d'un sink**
  (`mysqli_query(mysqli_real_escape_string($id))` n'est pas signalé).
- Une source affectée à une variable produit aussi un avertissement
  `unsanitized_source` (`severity: warning`).

Sinks reconnus par défaut : appels de fonction (`mysqli_query`, `eval`,
`system`, …) **et** constructions du langage (`echo`, `print`, `include`,
`require`). Les listes sont configurables dans `rules.yaml` (`sinks`,
`sanitizers`) ; à défaut, celles de `src/defaultRules.ts` s'appliquent.

### Analyse inter-procédurale

Le suivi traverse les appels de fonctions et méthodes définies dans le projet :

- Un **argument teinté** teinte le **paramètre** correspondant de l'appelé (les
  paramètres deviennent des relais). Un sink atteint à l'intérieur est signalé
  avec la **chaîne d'appel** (ex. `chemin: <global> → controller → find → run`).
- La **teinte du retour** se propage à l'appelant : `$x = f($teinté)` teinte
  `$x` si `f` renvoie une valeur teintée, mais pas si `f` la désinfecte.
- La récursion est bornée (garde de cycle) et les résumés de fonctions sont
  mémoïsés.

Limites connues : la résolution des méthodes se fait par nom (comme le graphe
de dépendances) ; une désinfection par **fonction utilisateur** appliquée
directement dans l'argument d'une construction (`echo maFonction($x)`) n'est pas
reconnue — préférer une variable intermédiaire (`$s = maFonction($x); echo $s;`).

## Prérequis

- **Visual Studio Code** : Version 1.85.0 ou supérieure.
- **Node.js** : Version 16.x ou 18.x (vérifie avec `node -v`).
- **Compilateur C/C++** : Nécessaire pour compiler les dépendances natives (`tree-sitter`, `tree-sitter-php`).
    - **Linux** : `sudo apt-get install build-essential python3`
    - **macOS** : `xcode-select --install`
    - **Windows** : `npm install -g windows-build-tools` (en mode administrateur)
- **TypeScript** : Version 5.4.5 (installée via `npm`).

## Installation

1. Clone ou télécharge ce projet dans un dossier, par exemple :
   ```bash
   git clone <url-du-dépôt> php-security-scanner
   cd php-security-scanner
   ```
   Ou décompresse le ZIP du projet.

2. Installe les dépendances :
   ```bash
   npm install
   ```
    - Si une erreur `ERESOLVE` apparaît, vérifie que `package.json` utilise :
      ```json
      {
        "tree-sitter": "0.21.1",
        "tree-sitter-php": "^0.22.6"
      }
      ```
      Puis réinstalle :
      ```bash
      rm -rf node_modules package-lock.json
      npm install
      ```

3. Compile l'extension :
   ```bash
   npm run compile
   ```
    - Cela génère les fichiers compilés dans le dossier `out/`.

## Utilisation

1. Ouvre un projet contenant des fichiers PHP dans VS Code.
2. Exécute la commande **PHP Security Scanner: Analyser le Workspace** :
    - Ouvre la palette de commandes (Ctrl+Shift+P).
    - Tape `PHP Security Scanner: Analyser le Workspace` et sélectionne-la.
3. Consulte les diagnostics dans le panneau des problèmes (Ctrl+Shift+M).
4. Clique sur l'ampoule à côté d'un diagnostic pour appliquer des corrections automatiques (ex. ajouter `htmlspecialchars` pour XSS).
5. L'analyse s'exécute automatiquement à la sauvegarde des fichiers PHP.

## Configuration

Modifie les paramètres dans `settings.json` de VS Code pour personnaliser l'analyse :

```json
{
  "phpSecurityScanner.vulnTypes": [
    "sql_injection",
    "xss",
    "rce",
    "file_inclusion",
    "auth_bypass",
    "session_fixation",
    "insecure_upload"
  ],
  "phpSecurityScanner.includePatterns": [
    "**/*.php"
  ],
  "phpSecurityScanner.excludePatterns": [
    "**/vendor/**",
    "**/node_modules/**"
  ],
  "phpSecurityScanner.rulesFile": "path/to/custom/rules.yaml"
}
```

Pour personnaliser les règles, édite `rules.yaml` ou spécifie un fichier personnalisé via `rulesFile`. Exemple :

```yaml
sources:
  - $_GET
  - $_POST
filters:
  xss:
    - htmlspecialchars
    - sanitize_text_field
sinks:
  xss:
    - echo
    - print
```

## Tests

Pour exécuter les tests unitaires :

```bash
npm test
```

Ou via VS Code :

1. Ouvre le panneau de débogage (Ctrl+Shift+D).
2. Sélectionne **Run Tests** et lance (F5).

**Note** : Les tests sont en cours de débogage. Certains peuvent échouer en raison de problèmes non encore résolus. Consulte la section **Problèmes connus** pour plus de détails.

## Développement

### Structure du projet

- `src/` : Code source.
    - `syntaxTreeParser.ts` : Extraction d'événements + analyse structurée (`parseModule`) depuis l'AST `tree-sitter`.
    - `taintRules.ts` : Décisions élémentaires (source / sink / désinfectant) partagées.
    - `taintTracker.ts` : Suivi de teinte intra-procédural.
    - `interproceduralTaint.ts` : Suivi de teinte inter-procédural (paramètres, retours, chaînes d'appel).
    - `defaultRules.ts` : Sinks et désinfectants par défaut.
    - `dependencyGraph.ts` : Construction du graphe de dépendances (résolution des symboles inter-fichiers).
    - `holonExporter.ts` : Mise en page et export du graphe de dépendances au format Holon.
    - `taintGraph.ts` : Export du graphe de teinte (source → sink) au format Holon.
    - `unifiedGraph.ts` : Vue unifiée (dépendances + surcouche de teinte).
    - `renderHtml.ts` : Rendu d'un aperçu HTML/SVG autonome (dépendances, teinte ou unifié).
    - `exportGraph.ts` : Point d'entrée CLI (`php-dep-graph`).
    - `types.ts` : Interfaces TypeScript (ex. `Vulnerability`, `Rules`, `HolonGraph`, `ModuleModel`).
    - `types/tree-sitter-php.d.ts` : Déclaration personnalisée pour `tree-sitter-php`.
- `tests/` : Tests unitaires (`taintTracker`, `interproceduralTaint`, `dependencyGraph`, `taintGraph`, `unifiedGraph`, `renderHtml`).
- `rules.yaml` : Règles par défaut pour l'analyse des vulnérabilités.
- `tsconfig.json` : Configuration TypeScript.
- `package.json` : Dépendances et scripts npm.

### Dépendances

- **Runtime** : `js-yaml`, `tree-sitter@0.21.1`, `tree-sitter-php@^0.22.6`, `vscode-uri`.
- **Développement** : `typescript`, `mocha`, `chai`, `ts-node`, types pour Node.js, VS Code, etc.

### Compilation

```bash
npm run compile
```

- Utilise `tsconfig.json` avec `rootDir: "."` pour inclure `src/` et `tests/`.
- Génère les fichiers `.js` et `.js.map` dans `out/`.

### Débogage

1. Ouvre le projet dans VS Code ou WebStorm.
2. Dans VS Code, lance **Run Extension** ou **Run Tests** depuis le panneau de débogage (Ctrl+Shift+D).
3. Dans WebStorm, configure un débogueur Node.js pour exécuter `npm test` ou l'extension.

### Publication

Pour créer un fichier `.vsix` :

```bash
npm install -g @vscode/vsce
vsce package
```

- Installe le `.vsix` dans VS Code via **Extensions > ... > Install from VSIX**.
- Publie sur le VS Code Marketplace avec `vsce publish`.

## Problèmes connus

- **Tests unitaires** : Certains tests dans `tests/taintTracker.test.ts` peuvent échouer. Les problèmes sont en cours d'investigation. Exécute `npm test` et partage la sortie pour aider au débogage.
- **Dépendances natives** : `tree-sitter` et `tree-sitter-php` nécessitent un compilateur C/C++. Si `npm install` échoue, vérifie les prérequis (ex. `build-essential` sur Linux).
- **TypeScript** : La déclaration de `tree-sitter-php@0.22.8` est corrigée via `src/types/tree-sitter-php.d.ts`. Si des erreurs comme `TS2714` réapparaissent, vérifie `tsconfig.json` (`paths` et `include`).
- **WebStorm** : Assure-toi que TypeScript utilise `tsconfig.json` (`File > Settings > Languages & Frameworks > TypeScript > Use tsconfig.json`).

## Contributions

Les contributions sont les bienvenues ! Ouvre une issue ou une pull request sur le dépôt GitHub pour signaler des bugs, proposer des améliorations, ou ajouter des tests.

## Licence

MIT
</xArtifact>

### Instructions pour utiliser le README

1. **Ajouter le README au projet** :
    - Crée ou remplace le fichier `README.md` dans `/home/rvv/WebstormProjects/typescript.PHP.Sec.Scan/` avec le contenu ci-dessus.
    - Enregistre-le avec l’encodage UTF-8.

2. **Vérifier le rendu** :
    - Ouvre `README.md` dans WebStorm ou VS Code pour confirmer que le Markdown s’affiche correctement.
    - Si tu as un dépôt GitHub, pousse le fichier et vérifie le rendu sur GitHub.

3. **Mettre à jour le ZIP (optionnel)** :
    - Ajoute ou remplace `README.md` dans ton dossier de projet.
    - Crée un nouveau ZIP :
      ```bash
      cd ~/WebstormProjects/typescript.PHP.Sec.Scan
      zip -r php-security-scanner.zip .
      ```
    - Vérifie que le ZIP inclut tous les fichiers, y compris le nouveau `README.md` :
      ```
      php-security-scanner/
      ├── .vscode/launch.json
      ├── .vscodeignore
      ├── package.json
      ├── tsconfig.json
      ├── README.md
      ├── src/extension.ts
      ├── src/taintTracker.ts
      ├── src/phpParser.ts
      ├── src/config.ts
      ├── src/types.ts
      ├── src/types/tree-sitter-php.d.ts
      ├── tests/taintTracker.test.ts
      ├── rules.yaml
      ```

### Prochaines étapes pour les tests

Tu as mentionné que les tests ne passent pas, et nous allons les déboguer après. Pour préparer cela, pourrais-tu exécuter :

```bash
npm test
```

Et partager la sortie complète des erreurs de test ? Cela m’aidera à identifier pourquoi les tests échouent (ex. problèmes dans `tests/taintTracker.test.ts`, erreurs d’exécution avec `tree-sitter`, ou assertions échouées). En attendant, voici quelques pistes possibles :

- **Vérification des dépendances** : Assure-toi que `package.json` utilise `tree-sitter@0.21.1` et `tree-sitter-php@^0.22.6` (artifact_id: `9629ad7c-4525-46ac-bece-1a14d820f6d1`).
- **Configuration des tests** : Confirme que `.vscode/launch.json` pointe vers `tests/**/*.test.ts` (artifact_id: `e45e1c17-3518-4153-bf13-7d3a0805911c`).
- **Problèmes potentiels** :
    - Les tests peuvent échouer si `tree-sitter-php@0.22.8` parse incorrectement le code PHP.
    - Des erreurs dans `taintTracker.test.ts` (ex. `get_tainted` mal configuré) pourraient causer des assertions échouées.
    - Un problème d’environnement (ex. compilateur C/C++ manquant) pourrait affecter l’exécution de `tree-sitter`.

## Stack

[![Stack](https://skillicons.dev/icons?i=ts,linux,vscode,nodejs&theme=dark)](https://skillicons.dev)