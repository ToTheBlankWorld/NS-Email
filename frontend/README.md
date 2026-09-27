# NS-Email Frontend

The NS-Email workstation UI — a dark-first, restrained forensic/SOC interface built with
Next.js (App Router), TypeScript, Tailwind CSS v4, and shadcn/ui.

## Structure

```
src/
├── app/                  # App Router: root layout + dashboard route
├── components/
│   ├── dashboard/        # dashboard sections (system status, capture, cases)
│   ├── layout/           # app shell: sidebar, top bar
│   ├── status/           # live backend status indicator
│   └── ui/               # shadcn/ui components
├── lib/                  # API client, shared hooks, formatting, nav config
└── styles/               # vendored shadcn base CSS (provenance noted in-file)
```

## Commands

```bash
npm install        # install dependencies
npm run dev        # development server → http://localhost:3000
npm run lint       # ESLint
npm run typecheck  # tsc --noEmit
npm run build      # production build
```

## Configuration

| Variable                   | Default                 | Purpose                          |
| -------------------------- | ----------------------- | -------------------------------- |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` | Backend API base URL for the browser |

## Stage 0 scope

The shell establishes the design language and honest empty states only: sidebar navigation
(implemented modules enabled, future modules marked "Soon"), a top bar with live backend
status, system status cards, and a capture upload empty state with client-side file
validation. There are **no fake statistics, findings, or AI outputs** — the UI reflects
exactly what the platform can do today. Ingestion wiring arrives with the capture-ingestion
stage.
