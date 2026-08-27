.PHONY: help install dev frontend test lint retrohunt deploy install-playwright docker-up docker-down

help:
	@echo "GARUDA CTI Platform - Command Shortcuts"
	@echo "========================================="
	@echo "make dev                 Run FastAPI backend with live reload"
	@echo "make frontend            Run React frontend development server"
	@echo "make test                Run complete pytest test suite"
	@echo "make lint                Run ruff & mypy type checking"
	@echo "make retrohunt           Run APT36 historical replay benchmark"
	@echo "make deploy              Deploy full stack to Vercel production"
	@echo "make install-playwright  Install headless Chromium browser"
	@echo "make docker-up           Start local Postgres & Redis services"
	@echo "make docker-down         Stop local Docker services"

install:
	pip install -r requirements.txt
	cd frontend && npm install

dev:
	uvicorn garuda.api.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test:
	pytest tests/ -v --asyncio-mode=auto

lint:
	ruff check garuda/ && mypy garuda/

retrohunt:
	python -m garuda.intelligence.retrohunt

deploy:
	vercel deploy --prod

install-playwright:
	playwright install chromium

docker-up:
	docker compose up -d

docker-down:
	docker compose down -v
