# Fraud Detector — Vercel Deployment

This is the same rule-based fraud detection engine from before, wrapped as a
small Flask API so Vercel actually has something to serve at your URL (the
404 you hit was because a plain `.py` script has no web entry point).

## Structure
```
.
├── api/
│   ├── index.py           <- Flask app (the actual web entry point)
│   └── fraud_detector.py  <- the engine itself, unchanged logic
├── vercel.json             <- tells Vercel to run api/index.py for every route
└── requirements.txt         <- Flask dependency
```

## Deploy
1. Put these files in a git repo (or a new folder) with this exact structure.
2. From that folder: `vercel` (or `vercel --prod`), or connect the repo in
   the Vercel dashboard and deploy as-is — no extra config needed, Vercel
   auto-detects Python via `vercel.json`.

## Endpoints (once deployed, e.g. `https://your-app.vercel.app`)

- `GET /` — health check, lists available endpoints
- `GET /api/demo` — runs the same synthetic transaction stream as before
  (velocity burst, circular ring, mule hub) and returns every alert as JSON
- `POST /api/detect` — send your own transactions:
  ```bash
  curl -X POST https://your-app.vercel.app/api/detect \
    -H "Content-Type: application/json" \
    -d '{
      "transactions": [
        {"txn_id": "T1", "sender": "acctA", "receiver": "acctB", "amount": 50000, "timestamp": 1000},
        {"txn_id": "T2", "sender": "acctB", "receiver": "acctC", "amount": 49000, "timestamp": 1010},
        {"txn_id": "T3", "sender": "acctC", "receiver": "acctA", "amount": 48000, "timestamp": 1020}
      ]
    }'
  ```
  Optional `"config": {...}` lets you override any threshold (window sizes,
  amount thresholds, cluster size, etc. — see the docstring at the top of
  `api/index.py`).

## Test locally first
```bash
pip install -r requirements.txt
cd api
python3 index.py
# then visit http://127.0.0.1:5000/ and http://127.0.0.1:5000/api/demo
```

## If you hit another Vercel error
Send me the exact error text/screenshot and I'll fix the config — Vercel's
Python support is picky about file layout (`vercel.json` + `api/` folder
naming matters), so most issues are structural, not logic bugs in the
detector itself.
