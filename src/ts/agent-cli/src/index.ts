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

program.parse(process.argv);
