import {SinkRule} from './types';

/**
 * Puits (sinks) par défaut : fonctions et constructions PHP où une donnée
 * teintée provoque une vulnérabilité, classées par catégorie. Utilisés quand
 * les règles ne définissent pas explicitement de `sinks`.
 */
export const DEFAULT_SINKS: SinkRule[] = [
    // Injection SQL
    {name: 'mysql_query', type: 'sql_injection'},
    {name: 'mysqli_query', type: 'sql_injection'},
    {name: 'mysqli_real_query', type: 'sql_injection'},
    {name: 'pg_query', type: 'sql_injection'},
    {name: 'sqlite_query', type: 'sql_injection'},
    {name: 'mssql_query', type: 'sql_injection'},
    {name: 'oci_parse', type: 'sql_injection'},

    // XSS (sorties)
    {name: 'echo', type: 'xss'},
    {name: 'print', type: 'xss'},
    {name: 'printf', type: 'xss'},
    {name: 'vprintf', type: 'xss'},
    {name: 'print_r', type: 'xss'},

    // Exécution de code / commandes (RCE)
    {name: 'eval', type: 'rce'},
    {name: 'assert', type: 'rce'},
    {name: 'exec', type: 'rce'},
    {name: 'system', type: 'rce'},
    {name: 'shell_exec', type: 'rce'},
    {name: 'passthru', type: 'rce'},
    {name: 'proc_open', type: 'rce'},
    {name: 'popen', type: 'rce'},
    {name: 'pcntl_exec', type: 'rce'},

    // Inclusion de fichiers
    {name: 'include', type: 'file_inclusion'},
    {name: 'include_once', type: 'file_inclusion'},
    {name: 'require', type: 'file_inclusion'},
    {name: 'require_once', type: 'file_inclusion'},
    {name: 'fopen', type: 'file_inclusion'},
    {name: 'file_get_contents', type: 'file_inclusion'},
    {name: 'file_put_contents', type: 'file_inclusion'},
    {name: 'readfile', type: 'file_inclusion'},
    {name: 'unlink', type: 'file_inclusion'}
];

/**
 * Fonctions et casts qui désinfectent une donnée. Quand une variable teintée
 * passe par l'un d'eux, elle est considérée comme sûre. Utilisés quand les
 * règles ne définissent pas explicitement de `sanitizers`.
 */
export const DEFAULT_SANITIZERS: string[] = [
    'htmlspecialchars',
    'htmlentities',
    'strip_tags',
    'mysqli_real_escape_string',
    'mysql_real_escape_string',
    'pg_escape_string',
    'pg_escape_literal',
    'addslashes',
    'intval',
    'floatval',
    'escapeshellarg',
    'escapeshellcmd',
    'filter_var',
    'urlencode',
    'rawurlencode',
    'preg_quote',
    'settype',
    '(int)',
    '(float)',
    '(bool)'
];
