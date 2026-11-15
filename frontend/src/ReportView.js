import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Link, Stack, Table, TableBody, TableCell,
  TableHead, TableRow, Typography,
} from '@mui/material';
import { coral, ink, mint, monoStack, pink, sky, yellow } from './theme';
import { Block, Sticker } from './ui';
import useCountUp from './useCountUp';

const VERDICTS = {
  Low: { word: 'clean fr', emoji: '😌', color: mint, line: 'nothing sus in here. not a guarantee, though.' },
  Medium: { word: 'kinda sus', emoji: '🤨', color: yellow, line: 'a few red flags. read the receipts before you open it.' },
  High: { word: 'cooked', emoji: '💀', color: coral, line: 'loads of red flags. do not open this one.' },
};

const SEVERITY_BG = { high: coral, medium: yellow, low: sky, info: '#fff' };

const srOnly = { position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap' };

function Heading({ children }) {
  return (
    <Typography component="h3" sx={{ fontSize: '1.6rem', fontWeight: 800, letterSpacing: '-0.02em', mb: 2 }}>
      {children}
    </Typography>
  );
}

function Verdict({ risk, result }) {
  const verdict = VERDICTS[risk.band];
  const score = useCountUp(risk.score);

  return (
    <Block bg={verdict.color} radius={32} shadow={10} sx={{ p: { xs: 3, md: 5 }, position: 'relative' }}>
      <Sticker bg={pink} rotate={4} sx={{ position: 'absolute', top: -18, right: { xs: 16, md: 36 } }}>
        {risk.band.toLowerCase()} risk
      </Sticker>

      <Typography sx={{ fontWeight: 600, wordBreak: 'break-word', mb: 1 }}>
        {result.filename} ({(result.size_bytes / 1024).toFixed(1)} KB)
      </Typography>

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ md: 'flex-end' }}>
        <Box>
          <Typography
            component="h2"
            sx={{ fontSize: 'clamp(3.2rem, 11vw, 7rem)', fontWeight: 800, lineHeight: 0.9, letterSpacing: '-0.045em' }}
          >
            {verdict.word} <span aria-hidden="true">{verdict.emoji}</span>
          </Typography>
          <Typography sx={{ mt: 1.5, fontSize: '1.15rem', fontWeight: 500 }}>{verdict.line}</Typography>
        </Box>
        <Typography
          aria-hidden="true"
          sx={{ fontSize: 'clamp(3.5rem, 10vw, 6rem)', fontWeight: 800, lineHeight: 0.9, letterSpacing: '-0.04em' }}
        >
          {score}
          <Typography component="span" sx={{ fontSize: '1.6rem', fontWeight: 700 }}>/100</Typography>
        </Typography>
      </Stack>
      <Box component="span" sx={srOnly}>{`${risk.band} risk, score ${risk.score} out of 100`}</Box>

      <Box
        role="progressbar"
        aria-label="Risk score"
        aria-valuenow={risk.score}
        aria-valuemin={0}
        aria-valuemax={100}
        sx={{ mt: 3, height: 24, border: `3px solid ${ink}`, borderRadius: 999, bgcolor: '#fff', overflow: 'hidden' }}
      >
        <Box
          sx={{
            width: `${score}%`,
            height: '100%',
            backgroundImage: `repeating-linear-gradient(45deg, ${ink} 0 10px, #3A2F7A 10px 20px)`,
          }}
        />
      </Box>
    </Block>
  );
}

function Receipts({ findings }) {
  return (
    <Block radius={16} sx={{ p: { xs: 2.5, md: 4 } }}>
      <Heading>the receipts</Heading>
      {findings.map((f, i) => (
        <Box
          key={i}
          sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', py: 1.75, borderTop: i ? `2px dashed ${ink}55` : 'none' }}
        >
          <Chip size="small" label={f.severity} sx={{ bgcolor: SEVERITY_BG[f.severity], mt: 0.25, minWidth: 72 }} />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{ fontWeight: 700 }}>{f.title}</Typography>
            {f.detail && <Typography variant="body2" color="text.secondary">{f.detail}</Typography>}
          </Box>
          {f.points > 0 && (
            <Sticker bg={pink} rotate={i % 2 ? 3 : -3} sx={{ fontSize: '0.85rem', boxShadow: `2px 2px 0 ${ink}` }}>
              +{f.points}
            </Sticker>
          )}
        </Box>
      ))}
    </Block>
  );
}

function HashRow({ label, value }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard access can be blocked; the hash is still selectable text
    }
  };

  return (
    <Box sx={{ mb: 2 }}>
      <Typography sx={{ fontWeight: 700 }}>{label}</Typography>
      <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'flex-start', mt: 0.5 }}>
        <Typography sx={{ fontFamily: monoStack, fontSize: '0.85rem', wordBreak: 'break-all', flex: 1 }}>{value}</Typography>
        <Button variant="outlined" size="small" onClick={copy} sx={{ py: 0.25, px: 1.5, fontSize: '0.85rem', boxShadow: `3px 3px 0 ${ink}`, flexShrink: 0 }}>
          {copied ? 'copied!' : 'copy'}
        </Button>
      </Box>
    </Box>
  );
}

function VirusTotal({ vt }) {
  if (!vt) {
    return <Typography>not hooked up on this server yet (set VT_API_KEY to turn it on).</Typography>;
  }
  if (vt.status === 'found') {
    const total = vt.malicious + vt.suspicious + vt.harmless + vt.undetected;
    return (
      <Typography>
        {vt.malicious} of {total} engines flagged this file as malicious.{' '}
        <Link href={vt.link} target="_blank" rel="noopener noreferrer">see the full list</Link>
      </Typography>
    );
  }
  if (vt.status === 'not_found') {
    return <Typography>never seen this exact file before. that tells us nothing either way.</Typography>;
  }
  return <Typography>{vt.reason || 'lookup unavailable right now.'}</Typography>;
}

function PeDetails({ pe }) {
  if (pe.error) return <Alert severity="warning">{pe.error}</Alert>;
  return (
    <>
      <Box sx={{ overflowX: 'auto' }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>section</TableCell>
              <TableCell align="right">entropy</TableCell>
              <TableCell>flags</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {pe.sections.map((s, i) => (
              <TableRow key={`${s.name}-${i}`}>
                <TableCell>{s.name || '(blank)'}</TableCell>
                <TableCell align="right" sx={{ bgcolor: s.entropy >= 7 ? coral : 'transparent', fontWeight: s.entropy >= 7 ? 800 : 400 }}>
                  {s.entropy}
                </TableCell>
                <TableCell>{[s.executable && 'executable', s.writable && 'writable'].filter(Boolean).join(', ') || '-'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
      <Typography sx={{ mt: 2 }}>
        {pe.import_function_count} imported functions from {pe.imports.length} DLLs
        {pe.imports.length > 0 && `: ${pe.imports.slice(0, 15).join(', ')}${pe.imports.length > 15 ? ', ...' : ''}`}
      </Typography>
      {pe.compile_time && (
        <Typography color="text.secondary" sx={{ mt: 0.5 }}>
          compile time claimed by the header: {pe.compile_time}
        </Typography>
      )}
    </>
  );
}

function PdfDetails({ pdf }) {
  const entries = Object.entries(pdf.keywords || {});
  return (
    <>
      <Typography>pages: {pdf.page_count ?? 'unknown'}</Typography>
      <Typography>
        risky markers: {entries.length ? entries.map(([k, n]) => `/${k} x${n}`).join(', ') : 'none found'}
      </Typography>
      <Typography color="text.secondary" sx={{ mt: 1 }}>{pdf.scan_note}</Typography>
      {pdf.text_sample && <Typography sx={{ mt: 1, fontStyle: 'italic' }}>text sample: {pdf.text_sample}</Typography>}
    </>
  );
}

function DocDetails({ doc }) {
  return (
    <>
      {doc.word_count !== undefined && <Typography>words: {doc.word_count}</Typography>}
      <Typography>macros: {doc.has_macros ? 'present' : 'none found'}</Typography>
      <Typography>embedded objects: {doc.embedded_objects?.length ? doc.embedded_objects.length : 'none found'}</Typography>
      {doc.note && <Typography color="text.secondary" sx={{ mt: 1 }}>{doc.note}</Typography>}
      {doc.text_sample && <Typography sx={{ mt: 1, fontStyle: 'italic' }}>text sample: {doc.text_sample}</Typography>}
    </>
  );
}

export default function ReportView({ result, onDownload }) {
  const { risk, hashes, details } = result;

  return (
    <Stack spacing={4} sx={{ mt: 7 }}>
      <Verdict risk={risk} result={result} />
      <Receipts findings={risk.findings} />

      <Box sx={{ display: 'grid', gap: 4, gridTemplateColumns: { xs: '1fr', md: '1.5fr 1fr' } }}>
        <Block radius={12} bg="#fff" sx={{ p: { xs: 2.5, md: 4 } }}>
          <Heading>file fingerprint</Heading>
          <HashRow label="SHA-256" value={hashes.sha256} />
          <HashRow label="MD5" value={hashes.md5} />
        </Block>
        <Block radius={20} bg={sky} sx={{ p: { xs: 2.5, md: 4 } }}>
          <Heading>virustotal says</Heading>
          <VirusTotal vt={result.virustotal} />
        </Block>
      </Box>

      <Block radius={16} sx={{ p: { xs: 2.5, md: 4 } }}>
        <Heading>under the hood</Heading>
        {details.pe && <PeDetails pe={details.pe} />}
        {details.pdf && <PdfDetails pdf={details.pdf} />}
        {details.document && <DocDetails doc={details.document} />}
      </Block>

      <Alert severity="info">{result.disclaimer}</Alert>

      <Box>
        <Button variant="contained" color="primary" onClick={onDownload}>download pdf report</Button>
      </Box>
    </Stack>
  );
}
