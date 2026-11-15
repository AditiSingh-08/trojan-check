import { render, screen } from '@testing-library/react';
import App from './App';
import ReportView from './ReportView';

// Keep the real network and PDF libraries out of the unit tests.
jest.mock('axios', () => ({ __esModule: true, default: { post: jest.fn() } }));
jest.mock('jspdf', () => ({ jsPDF: jest.fn() }));
// Skip the count-up animation so the final score renders immediately.
jest.mock('./useCountUp', () => ({ __esModule: true, default: (n) => n }));

beforeEach(() => {
  localStorage.clear();
});

test('shows the login form when there is no saved token', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /who dis/i })).toBeInTheDocument();
});

test('shows the upload screen when a token is saved', () => {
  localStorage.setItem('access_token', 'saved-token');
  render(<App />);
  expect(screen.getByRole('heading', { name: /is this file sus/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /check it/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /log out/i })).toBeInTheDocument();
});

const sampleResult = {
  filename: 'evil.exe',
  file_type: 'exe',
  size_bytes: 2048,
  hashes: { sha256: 'a'.repeat(64), sha1: 'b'.repeat(40), md5: 'c'.repeat(32) },
  virustotal: null,
  risk: {
    score: 80,
    band: 'High',
    findings: [
      { severity: 'high', title: 'Section names match a known packer', detail: 'Found: UPX0.', points: 25 },
      { severity: 'info', title: 'VirusTotal lookup unavailable', detail: 'No key.', points: 0 },
    ],
  },
  details: {
    pe: {
      sections: [{ name: 'UPX0', entropy: 7.9, raw_size: 0, virtual_size: 9000, executable: true, writable: true }],
      imports: [],
      import_function_count: 0,
      suspicious_imports: {},
      compile_time: null,
    },
  },
  disclaimer: 'Static analysis only.',
};

test('report shows the verdict, the findings and the hashes', () => {
  render(<ReportView result={sampleResult} onDownload={() => {}} />);
  expect(screen.getByText(/cooked/i)).toBeInTheDocument();
  expect(screen.getByText('Section names match a known packer')).toBeInTheDocument();
  expect(screen.getByText('+25')).toBeInTheDocument();
  expect(screen.getByText('UPX0')).toBeInTheDocument();
  expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
  expect(screen.getByRole('progressbar', { name: /risk score/i })).toHaveAttribute('aria-valuenow', '80');
});
