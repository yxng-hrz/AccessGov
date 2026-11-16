.PHONY: install seed run test docker-up docker-down

install:
	python -m pip install -r requirements.txt

seed:
	python scripts/seed_demo.py

run:
	uvicorn app.main:app --reload

test:
	python -m pytest -q

docker-up:
	docker compose up --build

docker-down:
	docker compose down
