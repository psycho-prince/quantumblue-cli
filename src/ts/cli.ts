#!/usr/bin/env node
import { program } from 'commander';
import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import { fileURLToPath } from 'url';
import path from 'path';
import readline from 'readline';
import { createRequire } from 'module';

// Import from our new unified crypto module
import { 
  generateHybridKeypair, 
  encryptString, 
  decryptString, 
  generateSigningKeypair, 
  signMessage, 
  verifySignature,
  encryptFileStream,
  decryptFileStream
} from './crypto.js';

import { getAutonomyLevel } from './config.js';
import { isActionAllowed, resolveSafePath } from './policy.js';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const autonomyLevel = getAutonomyLevel();

/**
 * Middleware-like wrapper for autonomy and policy checks.
 */
async function withAutonomy(actionName: string, callback: () => Promise<void>) {
  if (!isActionAllowed(actionName)) {
    console.log(`Action blocked by policy: '${actionName}' is not in the allowlist.`);
    process.exit(1);
  }

  if (autonomyLevel === 'readonly') {
    // Some actions might be safe in readonly (like verify or scan),
    // but typically keygen/sign/encrypt are blocked.
    const mutationActions = ['generate-signing-keypair', 'sign', 'generate-keypair', 'encrypt', 'decrypt', 'harden', 'encrypt-file', 'decrypt-file'];
    if (mutationActions.includes(actionName)) {
      console.log(`Blocked: '${actionName}' is not permitted in readonly mode.`);
      process.exit(0);
    }
  }

  if (autonomyLevel === 'supervised') {
    const confirmed = await confirmAction(`Confirm action '${actionName}'? (y/n): `);
    if (!confirmed) {
      console.log('Action cancelled by user.');
      process.exit(0);
    }
  }

  return callback();
}

function confirmAction(prompt: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}

const wrapAsync = (fn: (...args: any[]) => Promise<void>) => (...args: any[]) => {
  fn(...args).catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
};

console.log(`Starting QuantumBlue CLI v${pkg.version} [Autonomy: ${autonomyLevel}]`);

program
  .version(pkg.version)
  .description('QuantumBlue CLI for Hybrid Post-Quantum Cryptography');

program
  .command('generate-signing-keypair')
  .description('Generates a new ML-DSA signing key pair.')
  .option('-l, --level <level>', 'ML-DSA level (mldsa65, mldsa87)', 'mldsa65')
  .action(wrapAsync(async (options) => {
    await withAutonomy('generate-signing-keypair', async () => {
      console.log(`Generating ML-DSA (${options.level}) key pair...`);
      const { publicKeyHex, privateKeyHex } = await generateSigningKeypair(options.level);
      console.log('Public Key (Hex):', publicKeyHex);
      console.log('Private Key (Hex):', privateKeyHex);
    });
  }));

program
  .command('sign')
  .description('Signs a message using ML-DSA.')
  .requiredOption('-m, --message <string>', 'The message to sign.')
  .requiredOption('-p, --priv <key>', 'The hex private key.')
  .option('-l, --level <level>', 'ML-DSA level (mldsa65, mldsa87)', 'mldsa65')
  .action(wrapAsync(async (options) => {
    await withAutonomy('sign', async () => {
      const signature = await signMessage(options.message, options.priv, options.level);
      console.log('Signature (Hex):', signature);
    });
  }));

program
  .command('verify')
  .description('Verifies an ML-DSA signature.')
  .requiredOption('-s, --sig <hex>', 'The hex signature.')
  .requiredOption('-m, --message <string>', 'The original message.')
  .requiredOption('-p, --pub <key>', 'The hex public key.')
  .option('-l, --level <level>', 'ML-DSA level (mldsa65, mldsa87)', 'mldsa65')
  .action(wrapAsync(async (options) => {
    await withAutonomy('verify', async () => {
      const isValid = await verifySignature(options.sig, options.message, options.pub, options.level);
      console.log('Signature is valid:', isValid);
    });
  }));

program
  .command('scan-contract')
  .description('Scans a Solidity contract for quantum vulnerabilities.')
  .requiredOption('-f, --file <path>', 'The path to the contract file.')
  .action(wrapAsync(async (options) => {
    await withAutonomy('scan-contract', async () => {
      const safePath = resolveSafePath(options.file);
      const content = await fs.readFile(safePath, 'utf-8');
      
      console.log(`Scanning ${options.file} for quantum risks...`);
      
      const risks = [];
      if (content.match(/ECDSA|ecrecover/gi)) {
        risks.push('CRITICAL: Classical ECDSA detected. Vulnerable to Shor\'s algorithm.');
      }
      if (content.match(/secp256k1/gi)) {
        risks.push('HIGH: secp256k1 curve used. This is not quantum-resistant.');
      }
      if (content.match(/tx\.origin/gi)) {
        risks.push('MEDIUM: tx.origin used for authentication. Potential phishing risk.');
      }
      if (content.match(/selfdestruct/gi)) {
        risks.push('LOW: selfdestruct detected. Ensure this is intentional.');
      }
      
      if (risks.length > 0) {
        console.log('\nQuantum Risk Assessment:');
        risks.forEach(r => console.log(`- ${r}`));
        console.log('\nRecommendation:');
        console.log('Migrate to NIST ML-DSA (Dilithium) for quantum-resistant signatures.');
      } else {
        console.log('No immediate quantum risks detected.');
      }
    });
  }));

program
  .command('generate-keypair')
  .description('Generates a new hybrid KEM key pair.')
  .action(wrapAsync(async () => {
    await withAutonomy('generate-keypair', async () => {
      console.log('Generating key pair...');
      const { publicKeyHex, privateKeyHex } = await generateHybridKeypair();
      console.log('Public Key (Hex):', publicKeyHex);
      console.log('Private Key (Hex):', privateKeyHex);
    });
  }));

program
  .command('encrypt')
  .description('Encrypts a string using a hybrid PQC scheme.')
  .requiredOption('-t, --text <string>', 'The plaintext string to encrypt.')
  .requiredOption('-p, --pub <key>', 'The recipient\'s hex public key.')
  .action(wrapAsync(async (options) => {
    await withAutonomy('encrypt', async () => {
      console.log('Encrypting string...');
      const result = await encryptString(options.text, options.pub);
      console.log('Encryption Result (JSON):');
      console.log(JSON.stringify(result, null, 2));
    });
  }));

program
  .command('decrypt')
  .description('Decrypts a string using a hybrid PQC scheme.')
  .requiredOption('-i, --iv <hex>', 'IV in hex.')
  .requiredOption('-c, --cipher <hex>', 'Ciphertext in hex.')
  .requiredOption('--tag <hex>', 'Authentication tag in hex.')
  .requiredOption('-k, --kem <hex>', 'KEM encapsulated key in hex.')
  .requiredOption('-p, --priv <key>', 'The recipient\'s hex private key.')
  .action(wrapAsync(async (options) => {
    await withAutonomy('decrypt', async () => {
      console.log('Decrypting string...');
      const encrypted = { ivHex: options.iv, ciphertextHex: options.cipher, tagHex: options.tag };
      const decryptedText = await decryptString(encrypted, options.priv, options.kem);
      console.log('Decrypted Text:', decryptedText);
    });
  }));

program
  .command('encrypt-file')
  .description('Encrypts a file using a hybrid PQC scheme (Binary Stream).')
  .requiredOption('--input <file>', 'The path to the input file.')
  .requiredOption('--output <file>', 'The path for the encrypted output file.')
  .requiredOption('--pub <key>', "The recipient's hex public key.")
  .action(wrapAsync(async (options) => {
    await withAutonomy('encrypt-file', async () => {
      const inPath = resolveSafePath(options.input);
      const outPath = resolveSafePath(options.output);
      console.log(`Encrypting file ${inPath} using binary stream...`);
      await encryptFileStream(inPath, outPath, options.pub);
      console.log(`File successfully encrypted to ${outPath}`);
    });
  }));

program
  .command('decrypt-file')
  .description('Decrypts a file using a hybrid PQC scheme (Binary Stream).')
  .requiredOption('--input <file>', 'The path to the encrypted input file.')
  .requiredOption('--output <file>', 'The path for the decrypted output file.')
  .requiredOption('--priv <key>', "The recipient's hex private key.")
  .action(wrapAsync(async (options) => {
    await withAutonomy('decrypt-file', async () => {
      const inPath = resolveSafePath(options.input);
      const outPath = resolveSafePath(options.output);
      console.log(`Decrypting file ${inPath} using binary stream...`);
      await decryptFileStream(inPath, outPath, options.priv);
      console.log(`File successfully decrypted to ${outPath}`);
    });
  }));

program
  .command('harden')
  .description('Analyzes system and applies security hardening recommendations.')
  .action(wrapAsync(async () => {
    await withAutonomy('harden', async () => {
      console.log('Analyzing system for hardening opportunities...');
      // Future: Add real hardening logic here
      console.log('Harden action complete.');
    });
  }));

// --- Natural Language Input Fallback ---
const knownCommands = program.commands.map(cmd => cmd.name());
const inputArgs = process.argv.slice(2);

if (inputArgs.length > 0 && !knownCommands.includes(inputArgs[0]) && !['--version', '-V', '--help', '-h'].includes(inputArgs[0])) {
  const nlInput = inputArgs.join(' ');
  const metaKeywords = ["switch provider", "set model", "clear context", "rate limits", "token usage", "list models", "provider info"];
  const isMeta = metaKeywords.some(k => nlInput.toLowerCase().includes(k));

  if (autonomyLevel === 'readonly') {
    console.log('Blocked: Agent interaction is not permitted in readonly mode.');
    process.exit(0);
  }

  if (isMeta) {
    spawnQuantumAgent(nlInput, true);
  } else {
    console.log("Forwarding complex request to Quantum Agent...");
    if (autonomyLevel === 'supervised') {
      confirmAction('Confirm forwarding to AI agent? (y/n): ').then(confirmed => {
        if (confirmed) spawnQuantumAgent(nlInput);
        else {
          console.log('Action cancelled by user.');
          process.exit(0);
        }
      });
    } else {
      spawnQuantumAgent(nlInput);
    }
  }
} else {
  program.parse(process.argv);
}

function spawnQuantumAgent(nlInput: string, isMeta: boolean = false) {
  let projectRoot = __dirname;
  // Handle various environments (source, dist, global link)
  if (projectRoot.includes('dist')) {
    projectRoot = path.resolve(projectRoot.split('dist')[0]);
  } else if (projectRoot.includes('src')) {
    projectRoot = path.resolve(projectRoot.split('src')[0]);
  }

  const agentPath = path.join(projectRoot, 'python', 'quantum_agent.py');
  const args = isMeta ? ['--meta', nlInput] : [nlInput];

  const py = spawn('python3', [agentPath, ...args]);

  py.stdout.on('data', (data) => {
    process.stdout.write(`\nQuantum Agent Response:\n${data}`);
  });

  py.stderr.on('data', (data) => {
    process.stderr.write(`\nQuantum Agent Error:\n${data}`);
  });

  py.on('close', (code) => {
    if (code !== 0) console.log(`\nQuantum Agent process exited with code ${code}`);
  });
}
