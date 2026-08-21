#!/usr/bin/env node
// Test the crash-reporting script embedded in .github/workflows/fuzz-nightly.yml.
//
// That script only ever runs on a night when a harness crashes, which is the
// worst possible time to discover it is broken, and exercising it for real
// means filing an issue on the repo. So run it here against fixture artefact
// trees with the GitHub API stubbed.
//
// The script body is read out of the workflow file rather than copied, so this
// test cannot drift away from what CI actually runs.
//
//   node tests/ci/fuzz-report-test.js

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const repoRoot = path.join(__dirname, '..', '..');
const workflow = path.join(repoRoot, '.github', 'workflows', 'fuzz-nightly.yml');

// Pull the `script: |` block belonging to the "File crash issues" step.
function extractScript() {
    const lines = fs.readFileSync(workflow, 'utf8').split('\n');
    const step = lines.findIndex(l => l.trim() === '- name: File crash issues');
    if (step === -1) throw new Error('no "File crash issues" step in ' + workflow);
    const start = lines.findIndex((l, i) => i > step && l.trim() === 'script: |');
    if (start === -1) throw new Error('no "script: |" block after the step');

    const body = [];
    let indent = null;
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') { body.push(''); continue; }
        if (indent === null) indent = line.match(/^ */)[0];
        if (!line.startsWith(indent)) break;
        body.push(line.slice(indent.length));
    }
    return body.join('\n');
}

// actions/github-script compiles the body into an async function with these
// names in scope. Match that exactly.
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const script = new AsyncFunction('github', 'context', 'core', 'require', extractScript());

function makeStubs(openIssues) {
    const state = { calls: [], logs: [], failed: null };
    const github = {
        rest: {
            issues: {
                listForRepo: async () => ({ data: openIssues }),
                create: async a => { state.calls.push({ op: 'create', ...a }); },
                createComment: async a => { state.calls.push({ op: 'comment', ...a }); },
            },
        },
    };
    const context = {
        repo: { owner: 'Strykar', repo: 'pam_authnft' },
        serverUrl: 'https://github.com',
        runId: 424242,
    };
    const core = {
        info: m => state.logs.push(['info', m]),
        warning: m => state.logs.push(['warning', m]),
        setFailed: m => { state.failed = m; },
    };
    return { github, context, core, state };
}

// Build an artefacts/ tree shaped like what actions/download-artifact leaves
// behind under merge-multiple: true, which is every leg's files in one flat
// directory. That is unconditional; without merge-multiple the action only
// creates a directory per artefact when more than one matches, so the shape
// would depend on how many legs uploaded. A live run on a one-leg matrix is
// what caught that.
function makeFixture(legs) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-report-test-'));
    const dir = path.join(root, 'artefacts');
    fs.mkdirSync(dir, { recursive: true });
    for (const [harness, leg] of Object.entries(legs)) {
        if ('exit' in leg) fs.writeFileSync(path.join(dir, `${harness}.exit`), `${leg.exit}\n`);
        if ('log' in leg) fs.writeFileSync(path.join(dir, `${harness}.log`), leg.log);
        for (const f of leg.crashFiles || []) fs.writeFileSync(path.join(dir, f), 'x');
    }
    return root;
}

let passed = 0;
let failed = 0;

function check(name, ok, detail) {
    if (ok) { passed++; console.log(`  [PASS] ${name}`); }
    else { failed++; console.log(`  [FAIL] ${name}${detail ? ` :: ${detail}` : ''}`); }
}

async function scenario(name, legs, openIssues, assertions) {
    console.log(`\n[CASE] ${name}`);
    const root = legs === null
        ? fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-report-test-'))
        : makeFixture(legs);
    const stubs = makeStubs(openIssues);
    const cwd = process.cwd();
    process.chdir(root);
    try {
        await script(stubs.github, stubs.context, stubs.core, require);
    } finally {
        process.chdir(cwd);
    }
    assertions(stubs.state);
}

async function main() {
    await scenario(
        'two harnesses crash, one exits clean, one never reached the fuzz step',
        {
            fuzz_username: {
                exit: 77,
                log: 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602',
                crashFiles: ['fuzz_username-crash-deadbeef'],
            },
            fuzz_fragment: { exit: 1, log: 'runtime error: signed integer overflow' },
            fuzz_cgroup_path: { exit: 0, log: 'Done 1000000 runs' },
            fuzz_socket_inode: { log: 'apt-get failed' },
        },
        [],
        ({ calls, failed: setFailed }) => {
            check('the step does not fail', setFailed === null, setFailed);
            check('exactly two issues filed', calls.length === 2,
                JSON.stringify(calls.map(c => c.title)));
            const titles = calls.map(c => c.title).sort();
            check('one per crashed harness, named for it',
                JSON.stringify(titles) === JSON.stringify([
                    '[fuzz-nightly] fuzz_fragment crashed',
                    '[fuzz-nightly] fuzz_username crashed',
                ]), JSON.stringify(titles));
            check('a harness that exited 0 is not reported',
                !calls.some(c => String(c.title).includes('cgroup_path')));
            check('a leg with no recorded exit code is not reported',
                !calls.some(c => String(c.title).includes('socket_inode')));

            const u = calls.find(c => c.title.includes('username'));
            check('crash artefact filename reaches the issue',
                u.body.includes('fuzz_username-crash-deadbeef'));
            check('the log tail reaches the issue',
                u.body.includes('heap-buffer-overflow'));
            check('the run url reaches the issue', u.body.includes('actions/runs/424242'));
            check('labels are set',
                JSON.stringify(u.labels) === JSON.stringify(['fuzz-crash', 'bug']),
                JSON.stringify(u.labels));

            const f = calls.find(c => c.title.includes('fragment'));
            check('a crash with no saved input reads as (none)', f.body.includes('`(none)`'));
            check('both are new issues, not comments', calls.every(c => c.op === 'create'));
        });

    await scenario(
        'the same harness crashes again while its issue is still open',
        { fuzz_username: { exit: 77, log: 'again', crashFiles: ['fuzz_username-crash-cafe'] } },
        [{ number: 99, title: '[fuzz-nightly] fuzz_username crashed' }],
        ({ calls }) => {
            check('one API call', calls.length === 1, JSON.stringify(calls));
            check('it comments rather than opening a duplicate', calls[0].op === 'comment');
            check('on the issue that is already open', calls[0].issue_number === 99);
            check('the comment carries the new run url',
                calls[0].body.includes('actions/runs/424242'));
        });

    await scenario(
        'the fuzz job failed but every harness exited clean',
        { fuzz_username: { exit: 0, log: 'ok' } },
        [],
        ({ calls, logs, failed: setFailed }) => {
            check('nothing is filed', calls.length === 0, JSON.stringify(calls));
            check('it warns rather than failing', logs.some(l => l[0] === 'warning'),
                JSON.stringify(logs));
            check('the step does not fail', setFailed === null, setFailed);
        });

    await scenario(
        'a single crashed leg, the shape a one-harness run produces',
        { fuzz_username: { exit: 77, log: 'boom', crashFiles: ['fuzz_username-crash-abc'] } },
        [],
        ({ calls, failed: setFailed }) => {
            check('the step does not fail', setFailed === null, setFailed);
            check('one issue filed', calls.length === 1, JSON.stringify(calls.map(c => c.title)));
            check('the crash file is found', calls[0].body.includes('fuzz_username-crash-abc'));
        });

    await scenario(
        'no artefacts were downloaded at all',
        null,
        [],
        ({ calls, failed: setFailed }) => {
            check('nothing is filed', calls.length === 0);
            check('the step fails loudly', setFailed !== null);
        });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed) process.exit(1);
}

main().catch(e => { console.error(e); process.exit(1); });
