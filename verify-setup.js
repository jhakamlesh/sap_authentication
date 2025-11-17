
const fs = require('fs');
const path = require('path');

const requiredFiles = [
    'main.js',
    'server.js',
    'package.json',
    '.env',
    'config/auth.config.js',
    'models/User.js',
    'models/Session.js',
    'services/token.service.js',
    'services/session.service.js',
    'services/sap.service.js',
    'middlewares/auth.middleware.js',
    'middlewares/request-tracking.middleware.js',
    'routes/auth.routes.js',
    'strategies/sap.strategy.js',
    'utils/logger.js'
];

const requiredFolders = [
    'config',
    'models',
    'services',
    'middlewares',
    'routes',
    'strategies',
    'utils',
    'logs'
];

console.log('\n🔍 Checking Project Setup...\n');

// Check folders
console.log('📁 Checking Folders:');
let missingFolders = [];
requiredFolders.forEach(folder => {
    const exists = fs.existsSync(folder);
    console.log(`   ${exists ? '✅' : '❌'} ${folder}/`);
    if (!exists) {
        missingFolders.push(folder);
    }
});

console.log('\n📄 Checking Files:');
let missingFiles = [];
requiredFiles.forEach(file => {
    const exists = fs.existsSync(file);
    console.log(`   ${exists ? '✅' : '❌'} ${file}`);
    if (!exists) {
        missingFiles.push(file);
    }
});

// Check .env configuration
console.log('\n⚙️  Checking .env Configuration:');
if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf8');
    const requiredEnvVars = [
        'MONGODB_URI',
        'JWT_ACCESS_SECRET',
        'JWT_REFRESH_SECRET',
        'ENCRYPTION_KEY',
        'SAP_CLIENT_ID',
        'SAP_CLIENT_SECRET',
        'SAP_BASE_URL'
    ];

    requiredEnvVars.forEach(varName => {
        const exists = envContent.includes(varName);
        const hasValue = envContent.includes(`${varName}=`) &&
            !envContent.includes(`${varName}=your-`) &&
            !envContent.includes(`${varName}=\n`);
        console.log(`   ${hasValue ? '✅' : '⚠️ '} ${varName} ${hasValue ? '' : '(not configured)'}`);
    });
} else {
    console.log('   ❌ .env file not found');
}

// Summary
console.log('\n📊 Summary:');
if (missingFolders.length === 0 && missingFiles.length === 0) {
    console.log('   ✅ All files and folders present!');
} else {
    if (missingFolders.length > 0) {
        console.log(`   ❌ Missing ${missingFolders.length} folder(s): ${missingFolders.join(', ')}`);
        console.log('\n   Run this to create missing folders:');
        console.log(`   mkdir -p ${missingFolders.join(' ')}`);
    }
    if (missingFiles.length > 0) {
        console.log(`   ❌ Missing ${missingFiles.length} file(s):`);
        missingFiles.forEach(file => console.log(`      - ${file}`));
    }
}

// Check if node_modules exists
console.log('\n📦 Dependencies:');
const hasNodeModules = fs.existsSync('node_modules');
console.log(`   ${hasNodeModules ? '✅' : '❌'} node_modules ${hasNodeModules ? '' : '(run: npm install)'}`);

console.log('\n');

if (missingFolders.length === 0 && missingFiles.length === 0 && hasNodeModules) {
    console.log('🎉 Setup looks good! Try running: npm run dev\n');
} else {
    console.log('⚠️  Please fix the issues above before starting the server.\n');
}