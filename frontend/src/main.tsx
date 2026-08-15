// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { Suspense } from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import App from './App';
import './index.css';
import { registerServiceWorker } from './lib/pwa';
import { queryClient } from './lib/queryClient';

// Initialize i18n - must be imported before App renders
import './lib/i18n';

// The shared QueryClient (incl. the global pending-changes MutationCache hook)
// now lives in ./lib/queryClient so the auth store can clear it on logout.

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-screen bg-background">
          <div className="flex flex-col items-center gap-4">
            <div className="h-8 w-8 animate-spin rounded-full border-[2.5px] border-muted-foreground/70 border-t-transparent" />
          </div>
        </div>
      }
    >
      <ErrorBoundary level="root">
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </QueryClientProvider>
      </ErrorBoundary>
    </Suspense>
  </React.StrictMode>
);

// Install the service worker (production only) so FreeSDN is an installable PWA
// and can receive push notifications.
registerServiceWorker();
