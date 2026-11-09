.PHONY: setup train run eval test clean seed

setup:
	pip install -r requirements.txt

train:
	python eval/train_injection.py

seed:
	python scripts/demo_seed.py

test:
	pytest tests/ -v

eval:
	python eval/run_eval.py

run-gateway:
	uvicorn gateway.main:app --host 0.0.0.0 --port 8001 --reload

run-chat:
	streamlit run ui/chat.py --server.port 8501

run-dashboard:
	streamlit run ui/dashboard.py --server.port 8502

run:
	python scripts/run_all.py
