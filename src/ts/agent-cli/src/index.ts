import { Command } from 'commander';
import { Agent } from './agent.js';

const program = new Command();

program
  .name('claw')
  .description('OpenClaw CLI for secure autonomous agent execution')
  .version('0.1.0');

program.command('do')
  .description('Execute a task with the autonomous agent')
  .argument('<task>', 'The task string for the agent to execute')
  .action(async (task: string) => {
    console.log(`Starting agent for task: "${task}"`);
    const agent = new Agent();
    try {
      const result = await agent.run(task);
      console.log('Agent finished with result:', result);
    } catch (error: any) {
      console.error('Agent failed:', error.message);
      process.exit(1);
    }
  });

import { promises as fs } from 'fs';
import {
  generateHybridKeypair,
  fileEncrypt,
  fileDecrypt,
} from '../../crypto-high.js';
import { toHex, fromHex } from '../../pqc.js';


program.command('hybrid-keygen')
  .description('Generates a new hybrid PQC keypair (ML-KEM-768 + X25519) and prints it.')
  .action(() => {
    const { publicKey, secretKey } = generateHybridKeypair();
    console.log('--- Hybrid PQC Keypair ---');
    console.log('Public Key (hex):', publicKey);
    console.log('Secret Key (hex):', secretKey);
    console.log('\n⚠️  Store your secret key securely! Do not commit to version control. ⚠️');
  });

program.command('encrypt-file <inputPath> <outputPath>')
  .description('Encrypts a file using hybrid PQC for a given recipient public key.')
  .requiredOption('--pub <hex>', 'Recipient public key (hex)')
  .option('-f, --overwrite', 'Overwrite output file if it exists')
  .action(async (inputPath: string, outputPath: string, options: { pub: string, overwrite?: boolean }) => {
    try {
      if (!options.overwrite && await fs.access(outputPath).then(() => true).catch(() => false)) {
        console.error(`Error: Output file '${outputPath}' already exists. Use --overwrite to force.`);
        process.exit(1);
      }
      await fileEncrypt(inputPath, outputPath, options.pub);
      console.log(`✅ File '${inputPath}' encrypted to '${outputPath}'.`);
    } catch (error: any) {
      console.error('❌ File encryption failed:', error.message);
      process.exit(1);
    }
  });

program.command('decrypt-file <inputPath> <outputPath>')
  .description('Decrypts a file using hybrid PQC with your private key.')
  .requiredOption('--priv <hex>', 'Recipient private key (hex)')
  .option('-f, --overwrite', 'Overwrite output file if it exists')
  .action(async (inputPath: string, outputPath: string, options: { priv: string, overwrite?: boolean }) => {
    try {
      if (!options.overwrite && await fs.access(outputPath).then(() => true).catch(() => false)) {
        console.error(`Error: Output file '${outputPath}' already exists. Use --overwrite to force.`);
        process.exit(1);
      }
      await fileDecrypt(inputPath, outputPath, options.priv);
      console.log(`✅ File '${inputPath}' decrypted to '${outputPath}'.`);
    } catch (error: any) {
      console.error('❌ File decryption failed:', error.message);
      process.exit(1);
    }
  });

program.parse(process.argv);
