// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { Outlet } from 'react-router-dom';

export function AuthLayout() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800">
      <div className="w-full max-w-md space-y-8 px-4">
        {/* Logo */}
        <div className="text-center">
          <h1 className="text-4xl font-bold text-white">FreeSDN</h1>
          <p className="mt-2 text-slate-400">Unified Network Management</p>
        </div>
        
        {/* Auth Content */}
        <Outlet />
      </div>
      
      {/* Footer */}
      <div className="mt-8 space-y-1 text-center">
        <p className="text-sm text-slate-500">
          &copy; {new Date().getFullYear()} FreeSDN. All rights reserved.
        </p>
        <p className="text-xs text-slate-600">
          All trademarks are the property of their respective owners.
        </p>
      </div>
    </div>
  );
}
