import React from 'react';
import { Box } from '@mui/material';
import { ink } from './theme';

// A chunky outlined block with a hard offset shadow.
export function Block({ bg = '#fff', shadow = 6, radius = 14, sx, children, ...rest }) {
  return (
    <Box
      {...rest}
      sx={{
        bgcolor: bg,
        border: `3px solid ${ink}`,
        borderRadius: `${radius}px`,
        boxShadow: `${shadow}px ${shadow}px 0 ${ink}`,
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}

// A small tilted pill, like a sticker slapped on a laptop.
export function Sticker({ bg, rotate = -3, sx, children, ...rest }) {
  return (
    <Box
      component="span"
      {...rest}
      sx={{
        display: 'inline-block',
        bgcolor: bg,
        color: ink,
        border: `3px solid ${ink}`,
        borderRadius: 999,
        px: 1.75,
        py: 0.5,
        fontWeight: 800,
        fontSize: '0.95rem',
        lineHeight: 1.3,
        transform: `rotate(${rotate}deg)`,
        boxShadow: `3px 3px 0 ${ink}`,
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}
