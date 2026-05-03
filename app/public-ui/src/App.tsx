import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SkinProvider } from "./skins/SkinProvider";
import Layout from "./components/Layout";
import OnboardPage from "./pages/OnboardPage";
import HomePage from "./pages/HomePage";
import RecordDetailPage from "./pages/RecordDetailPage";
import DatasetPage from "./pages/DatasetPage";
import AdminPage from "./pages/AdminPage";
import IngestPage from "./pages/IngestPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SkinProvider>
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<OnboardPage />} />
              <Route path="/verify" element={<HomePage />} />
              <Route path="/record/:proof_id" element={<RecordDetailPage />} />
              <Route path="/dataset/:dataset_id" element={<DatasetPage />} />
              <Route path="/ingest" element={<IngestPage />} />
              <Route path="/admin" element={<AdminPage />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </SkinProvider>
    </QueryClientProvider>
  );
}
