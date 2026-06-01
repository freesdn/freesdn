const { spawnSync } = require('child_process');

// Build with --mode demo and capture the actual environment loaded
const result = spawnSync('npm', ['run', 'build:demo'], {
  stdio: 'pipe',
  encoding: 'utf-8'
});

console.log('Build output contains:');
console.log(result.stdout.substring(0, 500));

// Now check what's in the built index.html
const fs = require('fs');
const indexHtml = fs.readFileSync('dist/index.html', 'utf-8');
console.log('\n=== Built index.html ===');
console.log(indexHtml);
