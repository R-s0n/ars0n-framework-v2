const validateInput = (type, inputText) => {
  if (type === 'Company') {
    if (!/^[a-zA-Z0-9\s.-]+$/.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid Company name. Only letters, numbers, spaces, dots, and hyphens are allowed. Example: Google Inc'
      };
    }
  } else if (type === 'Wildcard') {
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!inputText.startsWith('*.')) {
      inputText = `*.${inputText}`;
    }
    if (!domainRegex.test(inputText.slice(2))) {
      return {
        valid: false,
        message: 'Invalid Wildcard format. Example: *.google.com'
      };
    }
  } else if (type === 'URL') {
    const urlRegex = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/[a-zA-Z0-9._/-]*)?$/;
    if (!urlRegex.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid URL. Example: https://example.google.com/path'
      };
    }
    if (!inputText.startsWith('http://') && !inputText.startsWith('https://')) {
      inputText = `https://${inputText}`;
    }
  } else {
    return {
      valid: false,
      message: 'Invalid selection. Please choose a type.'
    };
  }

  return {
    valid: true,
    message: ''
  };
};

export default validateInput;
  