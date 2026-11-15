import { createTheme } from '@mui/material/styles';

// Design tokens. Components import these directly so they also render
// correctly in tests, where no ThemeProvider is mounted.
export const ink = '#1B1340';
export const lilac = '#B9B4FF';
export const pink = '#FF3D8B';
export const yellow = '#FFE14D';
export const mint = '#3DF2B0';
export const coral = '#FF6B4A';
export const sky = '#9ED8FF';

export const fontStack = '"Bricolage Grotesque", "Segoe UI", system-ui, sans-serif';
export const monoStack = '"JetBrains Mono", Consolas, "Courier New", monospace';

const theme = createTheme({
  palette: {
    primary: { main: pink, contrastText: ink },
    secondary: { main: yellow, contrastText: ink },
    error: { main: coral, contrastText: ink },
    text: { primary: ink, secondary: '#4A4170' },
    background: { default: lilac, paper: '#FFFFFF' },
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily: fontStack,
    button: { textTransform: 'none', fontWeight: 800, fontSize: '1.05rem' },
  },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true, disableRipple: true },
      styleOverrides: {
        root: {
          border: `3px solid ${ink}`,
          borderRadius: 14,
          padding: '10px 24px',
          color: ink,
          boxShadow: `4px 4px 0 ${ink}`,
          transition: 'transform 80ms, box-shadow 80ms',
          '&:hover': { transform: 'translate(-2px, -2px)', boxShadow: `6px 6px 0 ${ink}` },
          '&:active': { transform: 'translate(4px, 4px)', boxShadow: `0 0 0 ${ink}` },
          '&:focus-visible': { outline: `3px solid ${ink}`, outlineOffset: 3 },
          '&.Mui-disabled': { opacity: 0.75, color: ink, border: `3px solid ${ink}` },
          '@media (prefers-reduced-motion: reduce)': { transition: 'none' },
        },
        containedPrimary: {
          backgroundColor: pink,
          '&:hover': { backgroundColor: pink },
          '&.Mui-disabled': { backgroundColor: pink },
        },
        outlined: {
          backgroundColor: '#fff',
          borderColor: ink,
          '&:hover': { backgroundColor: yellow, borderColor: ink },
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: '#fff',
          borderRadius: 14,
          '& .MuiOutlinedInput-notchedOutline': { borderWidth: 3, borderColor: ink },
          '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: ink },
          '&.Mui-focused': { boxShadow: `4px 4px 0 ${pink}` },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderWidth: 3, borderColor: ink },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: { color: ink, fontWeight: 600, '&.Mui-focused': { color: ink } },
      },
    },
    MuiChip: {
      styleOverrides: { root: { border: `2px solid ${ink}`, fontWeight: 800, color: ink } },
    },
    MuiAlert: {
      styleOverrides: {
        root: { border: `3px solid ${ink}`, borderRadius: 14, color: ink, fontWeight: 500, alignItems: 'center' },
        standardInfo: { backgroundColor: sky },
        standardError: { backgroundColor: '#FFC9BD' },
        standardWarning: { backgroundColor: yellow },
        standardSuccess: { backgroundColor: mint },
        icon: { color: ink },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderBottom: `2px solid ${ink}33`, color: ink },
        head: { fontWeight: 800 },
      },
    },
    MuiLink: {
      styleOverrides: {
        root: {
          color: ink,
          fontWeight: 700,
          textDecorationColor: pink,
          textDecorationThickness: 3,
          textUnderlineOffset: 3,
        },
      },
    },
  },
});

export default theme;
