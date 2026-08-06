const { exec } = require('child_process');
const child_process = require('child_process');
const cp = require('child_process');

// ruleid: mcp-nodejs-shell-string-interpolation
exec(`docker exec ${containerId} ls`, (err, out) => {});

// ruleid: mcp-nodejs-shell-string-interpolation
child_process.exec(`docker exec ${containerId} ls`, cb);

// ruleid: mcp-nodejs-shell-string-interpolation
child_process.exec('docker exec ' + containerId + ' ls', cb);

// ruleid: mcp-nodejs-shell-string-interpolation
cp.exec(`ls ${dir}`, cb);

// ok: mcp-nodejs-shell-string-interpolation
exec('docker ps -a', cb);

// ok: mcp-nodejs-shell-string-interpolation
spawn('docker', ['exec', containerId, 'ls']);
