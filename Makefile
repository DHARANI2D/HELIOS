.PHONY: build run stop test simulate clean

# Default: Dev run
run:
	docker-compose up --build

# Backend only (Local dev)
run-backend:
	cd backend && pip install . && uvicorn aegis.api.main:app --reload

# Frontend only (Local dev)
run-frontend:
	cd frontend && npm install && npm run dev

# Simulation
simulate:
	@echo "📡 Starting Real-Life AI Fleet Simulation..."
	python3 scripts/realistic_simulator.py

# Tests
test:
	cd backend && python3 verify_aegis_ultimate.py

# Cleanup
clean:
	docker-compose down
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "node_modules" -exec rm -rf {} +
