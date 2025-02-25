import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import Login from './login'; // Import the login component

// Material UI imports
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  CircularProgress,
  Alert,
  TextField,
  AppBar,
  Toolbar,
  IconButton,
} from '@mui/material';
import { CloudUpload } from '@mui/icons-material';
import MenuIcon from '@mui/icons-material/Menu';

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [token, setToken] = useState(localStorage.getItem('access_token') || '');

  // If the user is not authenticated, show the Login page
  if (!token) {
    return <Login onLoginSuccess={(newToken) => setToken(newToken)} />;
  }

  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setAnalysisResult(null);
    setErrorMsg('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('Please select a file before analyzing.');
      return;
    }
    setLoading(true);
    setErrorMsg('');
    setAnalysisResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post('http://127.0.0.1:8000/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${token}`,
        },
      });
      setAnalysisResult(response.data);
    } catch (error) {
      console.error('Error in Axios request:', error);
      const msg =
        error.response?.data?.detail || 'Error analyzing file. Please try again.';
      setErrorMsg(msg);
    }
    setLoading(false);
  };

  const downloadPDFReport = () => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text('Malware Analysis Report', 10, 20);
    doc.setFontSize(12);
    doc.text(`Filename: ${analysisResult.filename}`, 10, 30);
    doc.text(`File Type: ${analysisResult.file_type}`, 10, 40);

    if (analysisResult.file_type === 'exe') {
      doc.text(`Risk Factor: ${analysisResult.risk_factor}/100`, 10, 50);
      doc.text('YARA Analysis:', 10, 60);
      doc.text(`${analysisResult.risk_details?.yara || 'N/A'}`, 10, 70);
      if (analysisResult.pe_info) {
        if (analysisResult.pe_info.error) {
          doc.text(`PE Analysis Error: ${analysisResult.pe_info.error}`, 10, 80);
        } else {
          doc.text(`Sections: ${analysisResult.pe_info.sections.join(', ')}`, 10, 80);
          doc.text(`Imports: ${analysisResult.pe_info.imports.join(', ')}`, 10, 90);
        }
      }
      doc.text('Detailed Risk Breakdown:', 10, 100);
      doc.text(`Sections Risk: ${analysisResult.risk_details?.sections_risk || 0}`, 10, 110);
      doc.text(`Import Risk: ${analysisResult.risk_details?.import_risk || 0}`, 10, 120);
    } else if (analysisResult.file_type === 'pdf') {
      doc.text('PDF Analysis:', 10, 50);
      doc.text(`Number of Pages: ${analysisResult.pdf_info?.num_pages || 'N/A'}`, 10, 60);
      doc.text(`Text Sample: ${analysisResult.pdf_info?.text_sample || 'N/A'}`, 10, 70);
    } else if (analysisResult.file_type === 'docx') {
      doc.text('Document Analysis:', 10, 50);
      doc.text(`Word Count: ${analysisResult.doc_info?.word_count || 'N/A'}`, 10, 60);
      doc.text(`Text Sample: ${analysisResult.doc_info?.text_sample || 'N/A'}`, 10, 70);
    }
    doc.save('analysis_report.pdf');
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <AppBar position="static" sx={{ mb: 4 }}>
        <Toolbar>
          <IconButton
            edge="start"
            color="inherit"
            aria-label="menu"
            sx={{ mr: 2 }}
            onClick={() => console.log('Menu clicked')}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6">Malware Detection Service</Typography>
        </Toolbar>
      </AppBar>

      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" align="center" gutterBottom>
          Analyze Your Files
        </Typography>

        <Box
          component="form"
          onSubmit={handleSubmit}
          sx={{
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
            mt: 2,
          }}
        >
          {/* File input allowing multiple types */}
          <Button
            variant="contained"
            component="label"
            startIcon={<CloudUpload />}
            color="primary"
            sx={{ mt: 2 }}
          >
            Choose File
            <input
              type="file"
              hidden
              accept=".exe,.pdf,.doc,.docx"
              onChange={handleFileChange}
            />
          </Button>

          {selectedFile && (
            <TextField
              label="Selected File"
              variant="outlined"
              fullWidth
              value={selectedFile.name}
              InputProps={{
                readOnly: true,
              }}
            />
          )}

          <Button variant="contained" color="secondary" type="submit" disabled={loading}>
            {loading ? <CircularProgress size={24} /> : 'Analyze File'}
          </Button>
        </Box>

        {errorMsg && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {errorMsg}
          </Alert>
        )}

        {analysisResult && (
          <Box sx={{ mt: 4, p: 2, backgroundColor: '#f5f5f5' }}>
            <Typography variant="h5" gutterBottom>
              Analysis Report
            </Typography>
            <Paper elevation={1} sx={{ p: 2 }}>
              <Typography variant="subtitle1" color="textSecondary">
                Filename: {analysisResult.filename}
              </Typography>
              <Typography variant="subtitle1" color="textSecondary">
                File Type: {analysisResult.file_type}
              </Typography>

              {analysisResult.file_type === 'exe' && (
                <>
                  <Typography variant="h6" sx={{ mt: 1 }}>
                    Risk Factor: {analysisResult.risk_factor}/100
                  </Typography>
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2">YARA Analysis:</Typography>
                    <Typography variant="body2">
                      {analysisResult.risk_details?.yara || 'No YARA result.'}
                    </Typography>
                  </Box>
                  {analysisResult.pe_info && (
                    <Box sx={{ mt: 2 }}>
                      {analysisResult.pe_info.error ? (
                        <Typography variant="body2" color="error">
                          PE Analysis Error: {analysisResult.pe_info.error}
                        </Typography>
                      ) : (
                        <>
                          <Typography variant="subtitle2">PE Analysis:</Typography>
                          <Typography variant="body2">
                            Sections: {analysisResult.pe_info.sections.join(', ') || 'N/A'}
                          </Typography>
                          <Typography variant="body2">
                            Imports: {analysisResult.pe_info.imports.join(', ') || 'N/A'}
                          </Typography>
                        </>
                      )}
                    </Box>
                  )}
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2">Detailed Risk Breakdown:</Typography>
                    <Typography variant="body2">
                      Sections Risk: {analysisResult.risk_details?.sections_risk || 0}
                    </Typography>
                    <Typography variant="body2">
                      Import Risk: {analysisResult.risk_details?.import_risk || 0}
                    </Typography>
                  </Box>
                </>
              )}

              {analysisResult.file_type === 'pdf' && (
                <>
                  <Typography variant="subtitle2">PDF Analysis:</Typography>
                  <Typography variant="body2">
                    Number of Pages: {analysisResult.pdf_info?.num_pages || 'N/A'}
                  </Typography>
                  <Typography variant="body2">
                    Text Sample: {analysisResult.pdf_info?.text_sample || 'N/A'}
                  </Typography>
                </>
              )}

              {analysisResult.file_type === 'docx' && (
                <>
                  <Typography variant="subtitle2">Document Analysis:</Typography>
                  <Typography variant="body2">
                    Word Count: {analysisResult.doc_info?.word_count || 'N/A'}
                  </Typography>
                  <Typography variant="body2">
                    Text Sample: {analysisResult.doc_info?.text_sample || 'N/A'}
                  </Typography>
                </>
              )}
            </Paper>
            <Box sx={{ mt: 2 }}>
              <Button variant="outlined" onClick={downloadPDFReport}>
                Download PDF Report
              </Button>
            </Box>
          </Box>
        )}
      </Paper>

      <footer
        style={{
          marginTop: '16px',
          padding: '16px',
          textAlign: 'center',
          backgroundColor: '#f5f5f5',
        }}
      >
        <Typography variant="body2" color="textSecondary">
          © {new Date().getFullYear()} Malware Detection Service. All rights reserved.
        </Typography>
      </footer>
    </Container>
  );
}

export default App;