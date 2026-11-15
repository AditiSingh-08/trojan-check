import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Alert, Box, Button, CircularProgress, Container, Link, Typography } from '@mui/material';

import Login from './login';
import Dropzone from './Dropzone';
import ReportView from './ReportView';
import { Sticker } from './ui';
import { downloadPDFReport } from './pdfReport';
import { API_URL } from './api';
import { ink, yellow } from './theme';

const LOADING_LINES = ['sniffing the bytes...', 'counting entropy...', 'collecting receipts...', 'asking the horse...'];

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [notice, setNotice] = useState('');
  const [lineIndex, setLineIndex] = useState(0);
  const [token, setToken] = useState(localStorage.getItem('access_token') || '');

  useEffect(() => {
    if (!loading) return undefined;
    const id = setInterval(() => setLineIndex((i) => (i + 1) % LOADING_LINES.length), 1400);
    return () => clearInterval(id);
  }, [loading]);

  const handleLogout = (message = '') => {
    localStorage.removeItem('access_token');
    setToken('');
    setSelectedFile(null);
    setAnalysisResult(null);
    setErrorMsg('');
    setNotice(message);
  };

  if (!token) {
    return (
      <Login
        notice={notice}
        onLoginSuccess={(newToken) => {
          setNotice('');
          setToken(newToken);
        }}
      />
    );
  }

  const handleFile = (file) => {
    setSelectedFile(file);
    setAnalysisResult(null);
    setErrorMsg('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('pick a file first.');
      return;
    }
    setLoading(true);
    setLineIndex(0);
    setErrorMsg('');
    setAnalysisResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post(`${API_URL}/analyze`, formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setAnalysisResult(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        handleLogout('your session expired. log in again.');
        return;
      }
      setErrorMsg(
        error.response?.data?.detail || "couldn't analyze that. is the backend running?"
      );
    }
    setLoading(false);
  };

  return (
    <Container maxWidth="md" sx={{ pt: 3, pb: 6 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography component="div" sx={{ fontSize: '1.5rem', fontWeight: 800 }}>🐴 trojan.check</Typography>
        <Button variant="outlined" size="small" onClick={() => handleLogout()}>log out</Button>
      </Box>

      <Box sx={{ position: 'relative', mt: { xs: 5, md: 8 }, mb: { xs: 4, md: 5 } }}>
        <Sticker
          bg={yellow}
          rotate={5}
          sx={{ position: { xs: 'static', md: 'absolute' }, top: 0, right: 0, mb: { xs: 2, md: 0 } }}
        >
          inspected, never run
        </Sticker>
        <Typography
          component="h1"
          sx={{ fontSize: 'clamp(3rem, 10vw, 6.5rem)', fontWeight: 800, lineHeight: 0.92, letterSpacing: '-0.045em', maxWidth: 720 }}
        >
          is this file sus?
        </Typography>
        <Typography sx={{ mt: 2.5, fontSize: '1.2rem', fontWeight: 500, maxWidth: 560 }}>
          drop in an .exe, .pdf or Word file. you get a risk score and the receipts for it.
        </Typography>
      </Box>

      <Box component="form" onSubmit={handleSubmit}>
        <Dropzone file={selectedFile} onFile={handleFile} onReject={setErrorMsg} disabled={loading} />
        <Button
          type="submit"
          variant="contained"
          color="primary"
          size="large"
          disabled={loading}
          sx={{ mt: 4.5, width: { xs: '100%', sm: 'auto' }, fontSize: '1.25rem', px: 5 }}
        >
          {loading ? (
            <>
              <CircularProgress size={22} sx={{ color: ink, mr: 1.5 }} />
              {LOADING_LINES[lineIndex]}
            </>
          ) : (
            'check it'
          )}
        </Button>
      </Box>

      {errorMsg && <Alert severity="error" sx={{ mt: 3 }}>{errorMsg}</Alert>}

      {analysisResult && <ReportView result={analysisResult} onDownload={() => downloadPDFReport(analysisResult)} />}

      <Typography color="text.secondary" sx={{ mt: 8, fontWeight: 500 }}>
        made by{' '}
        <Link href="https://github.com/AditiSingh-08" target="_blank" rel="noopener noreferrer">aditi</Link>.
        static analysis only: nothing you upload gets run.
      </Typography>
    </Container>
  );
}

export default App;
