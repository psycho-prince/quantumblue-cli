import { program } from 'commander';
import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import { generateHybridKeypair, encryptString, decryptString } from './high-crypto.js'; // Relative import
import { getAutonomyLevel, AutonomyLevel } from './config.js';
import { isActionAllowed, resolveSafePath } from './policy.js';
import readline from 'readline';

const autonomyLevel = getAutonomyLevel();
console.log(`Starting QuantumBlue CLI with autonomy level: ${autonomyLevel}`);

// Helper function for supervised mode confirmation
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

// Helper to handle async operations and exit gracefully
const wrapAsync = (fn: (...args: any[]) => Promise<void>) => (...args: any[]) => {
  fn(...args).catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
};

program.version('1.0.0').description('QuantumBlue CLI for Hybrid Post-Quantum Cryptography');

program
  .command('generate-keypair')
  .description('Generates a new hybrid KEM key pair.')
  .action(wrapAsync(async () => {
    if (!isActionAllowed('generate-keypair')) {
      console.log("Action blocked by policy.");
      return;
    }
    console.log('Generating key pair...');
    const { publicKeyHex, privateKeyHex } = await generateHybridKeypair();
    console.log('Public Key (Hex):', publicKeyHex);
    console.log('Private Key (Hex):', privateKeyHex);
  }));

program
  .command('encrypt')
  .description('Encrypts a string using a hybrid PQC scheme.')
  .requiredOption('-t, --text <string>', 'The plaintext string to encrypt.')
  .requiredOption('-p, --pub <key>', 'The recipient\'s hex public key.')
  .action(wrapAsync(async (options) => {
    if (!isActionAllowed('encrypt')) {
      console.log("Action blocked by policy: 'encrypt' is not in the allowlist.");
      process.exit(1);
    }
    if (autonomyLevel === 'readonly') {
      console.log('Blocked: This action is not permitted in readonly mode.');
      process.exit(0);
    }
    if (autonomyLevel === 'supervised') {
      const confirmed = await confirmAction('Confirm encryption? (y/n): ');
      if (!confirmed) {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    }
    console.log('Encrypting string...');
    const result = await encryptString(options.text, options.pub);
    console.log('Encryption Result (JSON):');
    console.log(JSON.stringify(result, null, 2));
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
    if (!isActionAllowed('decrypt')) {
      console.log("Action blocked by policy: 'decrypt' is not in the allowlist.");
      process.exit(1);
    }
    if (autonomyLevel === 'readonly') {
      console.log('Blocked: This action is not permitted in readonly mode.');
      process.exit(0);
    }
    if (autonomyLevel === 'supervised') {
      const confirmed = await confirmAction('Confirm decryption? (y/n): ');
      if (!confirmed) {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    }
    console.log('Decrypting string...');
    const encrypted = { ivHex: options.iv, ciphertextHex: options.cipher, tagHex: options.tag };
    const decryptedText = await decryptString(encrypted, options.priv, options.kem);
    console.log('Decrypted Text:', decryptedText);
  }));

program
  .command('harden')
  .description('A mock command to demonstrate autonomy levels.')
  .action(wrapAsync(async () => {
    if (!isActionAllowed('harden')) {
      console.log("Action blocked by policy: 'harden' is not in the allowlist.");
      process.exit(1);
    }

    if (autonomyLevel === 'readonly') {
      console.log('Blocked: This action is not permitted in readonly mode.');
      process.exit(0);
    }

    if (autonomyLevel === 'supervised') {
      const confirmed = await confirmAction('This action will modify the system. Confirm? (y/n): ');
      if (!confirmed) {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    }

    console.log('Action approved. Proceeding with system modifications...');
    // const safeFilePath = resolveSafePath('some/user/provided/path.txt');
    // console.log(`Operating on safe path: ${safeFilePath}`);
    // Future file/system modification logic goes here
  }));

program
  .command('encrypt-file')
  .description('Encrypts a file using a hybrid PQC scheme.')
  .requiredOption('--input <file>', 'The path to the input file.')
  .requiredOption('--output <file>', 'The path for the encrypted output file.')
  .requiredOption('--pub <key>', "The recipient's hex public key.")
  .action(wrapAsync(async (options) => {
    if (!isActionAllowed('encrypt-file')) {
      console.log("Action blocked by policy.");
      process.exit(1);
    }
    if (autonomyLevel === 'readonly') {
      console.log('Blocked: This action is not permitted in readonly mode.');
      process.exit(0);
    }
    if (autonomyLevel === 'supervised') {
      const confirmed = await confirmAction(`Confirm encrypting ${options.input}? (y/n): `);
      if (!confirmed) {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    }
    const inPath = resolveSafePath(options.input);
    const outPath = resolveSafePath(options.output);
    console.log(`Encrypting file ${inPath}...`);
    const plaintext = await fs.readFile(inPath, 'utf-8');
    const result = await encryptString(plaintext, options.pub);
    await fs.writeFile(outPath, JSON.stringify(result, null, 2));
    console.log(`File successfully encrypted to ${outPath}`);
  }));

program
  .command('decrypt-file')
  .description('Decrypts a file using a hybrid PQC scheme.')
  .requiredOption('--input <file>', 'The path to the encrypted input file.')
  .requiredOption('--output <file>', 'The path for the decrypted output file.')
  .requiredOption('--priv <key>', "The recipient's hex private key.")
  .action(wrapAsync(async (options) => {
    if (!isActionAllowed('decrypt-file')) {
      console.log("Action blocked by policy.");
      process.exit(1);
    }
     if (autonomyLevel === 'readonly') {
      console.log('Blocked: This action is not permitted in readonly mode.');
      process.exit(0);
    }
    if (autonomyLevel === 'supervised') {
      const confirmed = await confirmAction(`Confirm decrypting ${options.input}? (y/n): `);
      if (!confirmed) {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    }
    const inPath = resolveSafePath(options.input);
    const outPath = resolveSafePath(options.output);
    console.log(`Decrypting file ${inPath}...`);
    const encryptedFile = JSON.parse(await fs.readFile(inPath, 'utf-8'));
    const decryptedText = await decryptString(encryptedFile, options.priv, encryptedFile.kemCiphertextHex);
    await fs.writeFile(outPath, decryptedText);
    console.log(`File successfully decrypted to ${outPath}`);
  }));

// --- Natural Language Input Fallback ---
const knownCommands = program.commands.map(cmd => cmd.name());
const inputArgs = process.argv.slice(2);

// If the first argument is not a known command and there are arguments, treat it as natural language
if (inputArgs.length > 0 && !knownCommands.includes(inputArgs[0])) {
  const nlInput = inputArgs.join(' ');
  console.log("Forwarding complex request to Quantum Agent...");

  // Autonomy check before spawning the agent
  if (autonomyLevel === 'readonly') {
    console.log('Blocked: Agent interaction is not permitted in readonly mode.');
    process.exit(0);
  }
  if (autonomyLevel === 'supervised') {
    confirmAction('Confirm forwarding to AI agent? (y/n): ').then(confirmed => {
      if (confirmed) {
        spawnQuantumAgent(nlInput);
      } else {
        console.log('Action cancelled by user.');
        process.exit(0);
      }
    });
  } else { // full autonomy
    spawnQuantumAgent(nlInput);
  }
} else {
  program.parse(process.argv);
}

function spawnQuantumAgent(nlInput: string) {
  const py = spawn('python3', ['python/quantum_agent.py', nlInput]);

  py.stdout.on('data', (data) => {
    console.log(`Quantum Agent Response:\n${data}`);
  });

  py.stderr.on('data', (data) => {
    console.error(`Quantum Agent Error:\n${data}`);
  });

  py.on('close', (code) => {
    if (code !== 0) {
      console.log(`Quantum Agent process exited with code ${code}`);
    }
  });
}
