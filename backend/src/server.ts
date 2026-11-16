import { app } from './app';
import { env } from './config/env';
import { disconnectDatabase } from './config/prisma';

const server = app.listen(env.PORT, () => {
  console.log(`Tourist Mobile API listening on http://localhost:${env.PORT}`);
});

async function shutdown(signal: string): Promise<void> {
  console.log(`${signal} received. Shutting down gracefully...`);

  server.close(async () => {
    await disconnectDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));