import { useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SkinProvider } from "./skins/SkinProvider";
import { EasterEggContext } from "./context/EasterEggContext";
import { useEasterEggs } from "./hooks/useEasterEggs";
import StartupGate from "./components/StartupGate";
import Layout from "./components/Layout";
import GodmodeOverlay from "./components/GodmodeOverlay";
import Win95OasisPopup from "./components/Win95OasisPopup";
import GunterBadge from "./components/GunterBadge";
import HomePage from "./pages/HomePage";
import RecordDetailPage from "./pages/RecordDetailPage";
import DatasetPage from "./pages/DatasetPage";
import AdminPage from "./pages/AdminPage";
import IngestPage from "./pages/IngestPage";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

function EasterEggLayer() {
  const eggs = useEasterEggs();

  // Bridge hook events to DOM events consumed by GlitchMentorPopups
  useEffect(() => {
    if (eggs.mayhemFired) {
      window.dispatchEvent(new CustomEvent("olympus:mayhem"));
      eggs.dismissMayhem();
    }
  }, [eggs, eggs.mayhemFired]);

  useEffect(() => {
    if (eggs.anorakFired) {
      window.dispatchEvent(new CustomEvent("olympus:anorak"));
      eggs.dismissAnorak();
    }
  }, [eggs, eggs.anorakFired]);

  return (
    <EasterEggContext.Provider value={eggs}>
      <BrowserRouter>
        <StartupGate>
          <Layout>
            <Routes>
              <Route path="/" element={<IngestPage />} />
              <Route path="/verify" element={<HomePage />} />
              <Route path="/record/:proof_id" element={<RecordDetailPage />} />
              <Route path="/dataset/:dataset_id" element={<DatasetPage />} />
              <Route path="/keys" element={<AdminPage />} />
            </Routes>
          </Layout>
        </StartupGate>
      </BrowserRouter>

      {/* Global easter egg layers — render outside router so they cover everything */}
      {eggs.godmode && <GodmodeOverlay onDismiss={eggs.dismissGodmode} />}
      {eggs.win95Popup && <Win95OasisPopup onDismiss={eggs.dismissWin95} />}
      {eggs.gunterUnlocked && <GunterBadge />}
    </EasterEggContext.Provider>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SkinProvider>
        <EasterEggLayer />
      </SkinProvider>
    </QueryClientProvider>
  );
}
