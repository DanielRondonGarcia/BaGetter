const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '../..');
const release = fs.readFileSync(path.join(root, '.github/workflows/release.yml'), 'utf8');
const build = fs.readFileSync(path.join(root, '.github/workflows/main.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8').replace(/\r\n/g, '\n');

function job(name) {
  const lines = release.split(/\r?\n/);
  const start = lines.indexOf(`  ${name}:`);
  assert(start >= 0, `Missing job: ${name}`);
  let end = start + 1;
  while (end < lines.length && !/^  [a-z_]+:$/.test(lines[end])) end++;
  return lines.slice(start, end).join('\n');
}

test('fork releases cannot publish charts into the upstream chart repository', () => {
  assert.match(job('release_helm_chart'), /github\.repository == 'bagetter\/BaGetter'/);
  assert.match(job('release_helm_chart'), /github\.ref_type == 'tag'/);
});

test('Docker releases remain enabled for forks and build both supported architectures', () => {
  const docker = job('release_docker_image');
  assert.match(docker, /if: \$\{\{ github\.ref_type == 'tag' \}\}/);
  assert.match(docker, /platforms: linux\/amd64,linux\/arm64/);
  assert.match(docker, /ghcr\.io\/\$\{\{ env\.REPO_OWNER_LOWER \}\}\/bagetter:latest/);
});

test('published Docker metadata identifies the actual release repository and commit', () => {
  const docker = job('release_docker_image');
  assert(docker.includes('org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}'));
  assert(docker.includes('org.opencontainers.image.revision=${{ github.sha }}'));
  assert(docker.includes('org.opencontainers.image.version=${{ needs.version.outputs.RELEASE_VERSION }}'));
});

test('Docker stores scan history alongside existing persistent data by default', () => {
  assert.match(dockerfile, /^ENV Vulnerabilities__History__Path="\/data\/security-history"$/m);
  assert.match(dockerfile, /ENV Storage__Path "\/data"/);
});

test('git-cliff only receives inputs supported by its pinned action version', () => {
  const changelog = job('release_zip').split('      - name: Generate changelog with git-cliff')[1]
    .split('      - name: Create release')[0];
  assert.match(changelog, /uses: tj-actions\/git-cliff@v2\.2\.0/);
  assert.doesNotMatch(changelog, /^\s+(config|working-dir):/m);
});

test('Build and Release verify the release configuration before delivering artifacts', () => {
  const command = 'node --test tests/release-config/release-workflow.test.cjs';
  assert(build.includes(command));
  assert(job('verify').includes(command));
  assert.match(job('release_docker_image'), /needs: \[version, verify\]/);
});
