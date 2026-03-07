1. Start in dev mode (no rebuild needed for future code changes):

docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres neo4j recon-orchestrator kali-sandbox agent webapp

2. Run this after any .env change:

docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate postgres neo4j recon-orchestrator kali-sandbox agent webapp

3. Code change in Python → docker compose restart agent

4. Shut down → docker compose down