import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SkinProvider } from "./skins/SkinProvider";
import DbErrorGate from "./components/DbErrorGate";
import StartupGate from "./components/StartupGate";
import Layout from "./components/Layout";
import InitialSecretsModal from "./components/InitialSecretsModal";
import StartupErrorScreen from "./components/StartupErrorScreen";
import ScopeBanner from "./components/ScopeBanner";
import HomePage from "./pages/HomePage";
import RecordDetailPage from "./pages/RecordDetailPage";
import DatasetPage from "./pages/DatasetPage";
import AdminPage from "./pages/AdminPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import CredentialsPage from "./pages/CredentialsPage";
import IngestPage from "./pages/IngestPage";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SkinProvider>
        <BrowserRouter>
          <StartupErrorScreen>
          <DbErrorGate>
          <StartupGate>
            <InitialSecretsModal />
            <ScopeBanner />
            <Layout>
              <Routes>
                <Route path="/" element={<Navigate to="/verify" replace />} />
                <Route path="/commit" element={<IngestPage />} />
                <Route path="/verify" element={<HomePage />} />
                <Route path="/record/:proof_id" element={<RecordDetailPage />} />
                <Route path="/dataset/:dataset_id" element={<DatasetPage />} />
                <Route path="/keys" element={<AdminPage />} />
                <Route path="/admin/users" element={<AdminUsersPage />} />
                <Route path="/credentials" element={<CredentialsPage />} />
              </Routes>
            </Layout>
          </StartupGate>
          </DbErrorGate>
          </StartupErrorScreen>
        </BrowserRouter>
      </SkinProvider>
    </QueryClientProvider>
  );
}
