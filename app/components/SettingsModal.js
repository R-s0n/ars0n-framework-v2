import React from 'react';
import { Accordion, AccordionSummary, AccordionDetails, Typography, Box } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

const SettingsModal = () => {
  return (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography>Custom HTTP Settings Support</Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body2" component="div">
          <strong>Tools that support both custom User Agent and custom headers:</strong>
          <ul>
            <li>HTTPX - Used for live web server discovery</li>
            <li>Nuclei - Used for taking screenshots</li>
            <li>GoSpider - Used for JavaScript link discovery</li>
          </ul>

          <strong>Tools that support only custom User Agent:</strong>
          <ul>
            <li>CeWL - Used for custom wordlist generation</li>
          </ul>

          <strong>Tools that do not support custom HTTP settings:</strong>
          <ul>
            <li>GAU - Uses its own HTTP client settings</li>
            <li>Amass - Uses its own DNS resolution</li>
            <li>Subfinder - Uses its own DNS resolution</li>
            <li>Sublist3r - Uses its own DNS resolution</li>
            <li>Assetfinder - Uses its own DNS resolution</li>
            <li>CTL - Uses certificate transparency logs</li>
            <li>ShuffleDNS - Uses DNS resolution only</li>
            <li>Subdomainizer - Parses JavaScript files locally</li>
          </ul>

          <Box mt={2}>
            <Typography variant="body2" color="textSecondary">
              Note: Tools that focus on DNS resolution or certificate transparency logs don't make direct HTTP requests, 
              so they don't use custom HTTP settings. Tools that use their own HTTP clients have their own configuration 
              methods and don't accept custom headers or user agents through command line flags.
            </Typography>
          </Box>
        </Typography>
      </AccordionDetails>
    </Accordion>
  );
};

export default SettingsModal; 