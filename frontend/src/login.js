import React, { useState } from 'react';
import axios from 'axios';
import { Alert, Box, Button, TextField, Typography } from '@mui/material';
import { API_URL } from './api';
import { yellow } from './theme';
import { Block, Sticker } from './ui';

function Login({ onLoginSuccess, notice }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const demoHint = process.env.REACT_APP_DEMO_HINT;

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg('');
    try {
      const response = await axios.post(
        `${API_URL}/token`,
        new URLSearchParams({ username, password }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const { access_token } = response.data;
      localStorage.setItem('access_token', access_token);
      onLoginSuccess(access_token);
    } catch (error) {
      console.error('Login error:', error);
      setErrorMsg(
        error.response?.data?.detail || "couldn't reach the server. is the backend running?"
      );
    }
    setLoading(false);
  };

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 2 }}>
      <Box sx={{ width: '100%', maxWidth: 470, position: 'relative' }}>
        <Typography sx={{ fontSize: '1.5rem', fontWeight: 800, mb: 2 }}>🐴 trojan.check</Typography>

        <Block radius={28} shadow={10} sx={{ p: { xs: 3, sm: 4.5 }, position: 'relative' }}>
          <Sticker
            bg={yellow}
            rotate={6}
            sx={{ position: 'absolute', top: -20, right: { xs: 12, sm: -16 } }}
          >
            files never run
          </Sticker>

          <Typography
            component="h1"
            sx={{ fontSize: 'clamp(3rem, 9vw, 4.2rem)', fontWeight: 800, lineHeight: 0.92, letterSpacing: '-0.045em' }}
          >
            who dis?
          </Typography>
          <Typography sx={{ mt: 1.5, mb: 3, fontWeight: 500 }}>log in to check a file.</Typography>

          {notice && <Alert severity="info" sx={{ mb: 2 }}>{notice}</Alert>}
          {demoHint && <Alert severity="warning" sx={{ mb: 2 }}>{demoHint}</Alert>}
          {errorMsg && <Alert severity="error" sx={{ mb: 2 }}>{errorMsg}</Alert>}

          <Box component="form" onSubmit={handleLogin} sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
            <TextField label="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
            <TextField label="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <Button variant="contained" color="primary" type="submit" size="large" disabled={loading} sx={{ mt: 1, fontSize: '1.2rem' }}>
              {loading ? 'checking...' : 'let me in'}
            </Button>
          </Box>
        </Block>
      </Box>
    </Box>
  );
}

export default Login;
