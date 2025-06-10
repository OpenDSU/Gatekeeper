const { execSync } = require('child_process');
const { rmSync } = require('fs');
const path = require('path');
const config = require('./config.json');
function getRepoName(url) {
    return url
        .trim()
        .replace(/\.git$/, '')        // Remove .git suffix if present
        .split('/')
        .pop();                        // Get last path segment
}
const authenticatorDir = path.join(__dirname, "authenticator");
const gitUrl = 'https://github.com/OpenDSU/authenticator.git';

try {
    rmSync(authenticatorDir, { recursive: true, force: true });
    console.log('Cloning authenticator repo...');
    execSync(`git clone ${gitUrl} ${authenticatorDir}`, { stdio: 'inherit' });
    console.log('Running npm install...');
    execSync(`npm install`, { cwd: authenticatorDir, stdio: 'inherit' });

    if(config.adminComponent){
        const adminComponentDir = path.join(__dirname, getRepoName(config.adminComponent));
        rmSync(adminComponentDir, { recursive: true, force: true });
        console.log('Cloning AdminComponent repo...');
        execSync(`git clone ${config.adminComponent} ${adminComponentDir}`, { stdio: 'inherit' });
    } else {
        console.error('AdminComponent URL is not provided in config.json, skipping cloning AdminComponent repo.');
    }


    console.log('Postinstall complete.');
} catch (err) {
    console.error('Postinstall failed:', err.message);
    process.exit(1);
}