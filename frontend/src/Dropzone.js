import React, { useState } from 'react';
import { Box, Typography } from '@mui/material';
import { ink, yellow } from './theme';

const ALLOWED = ['.exe', '.pdf', '.doc', '.docx'];

export default function Dropzone({ file, onFile, onReject, disabled }) {
  const [over, setOver] = useState(false);

  const accept = (picked) => {
    if (!picked) return;
    const dot = picked.name.lastIndexOf('.');
    const ext = dot >= 0 ? picked.name.slice(dot).toLowerCase() : '';
    if (!ALLOWED.includes(ext)) {
      onReject(`nope, ${ext || 'that'} files aren't supported. use .exe, .pdf, .doc or .docx.`);
      return;
    }
    onFile(picked);
  };

  return (
    <Box
      component="label"
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        if (!disabled) accept(e.dataTransfer.files[0]);
      }}
      sx={{
        position: 'relative',
        display: 'block',
        cursor: disabled ? 'default' : 'pointer',
        border: `3px dashed ${ink}`,
        borderRadius: '28px',
        bgcolor: over ? yellow : '#fff',
        p: { xs: 4, md: 7 },
        textAlign: 'center',
        boxShadow: `8px 8px 0 ${ink}`,
        transition: 'background-color 150ms',
        '&:focus-within': { outline: `3px solid ${ink}`, outlineOffset: 5 },
      }}
    >
      <input
        type="file"
        accept=".exe,.pdf,.doc,.docx"
        disabled={disabled}
        onChange={(e) => {
          accept(e.target.files[0]);
          e.target.value = '';
        }}
        style={{ position: 'absolute', width: 1, height: 1, opacity: 0, overflow: 'hidden' }}
      />
      <Typography component="div" sx={{ fontSize: '3.2rem', lineHeight: 1 }} aria-hidden="true">
        {over ? '👇' : '📥'}
      </Typography>
      {file ? (
        <>
          <Typography sx={{ mt: 1.5, fontSize: '1.7rem', fontWeight: 800, wordBreak: 'break-word' }}>
            {file.name}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.5 }}>
            {(file.size / 1024).toFixed(1)} KB. click or drop another file to swap it.
          </Typography>
        </>
      ) : (
        <>
          <Typography sx={{ mt: 1.5, fontSize: '1.9rem', fontWeight: 800 }}>
            {over ? 'let go, we got it' : 'drop a file here'}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.5 }}>
            or click to browse. .exe .pdf .doc .docx, up to 10 MB.
          </Typography>
        </>
      )}
    </Box>
  );
}
